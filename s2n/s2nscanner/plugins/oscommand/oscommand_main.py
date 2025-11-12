"""
OS Command Injection Plugin
---------------------------
- 내부 링크를 크롤링하면서 파라미터를 수집하고,
  OS Command Injection 징후를 탐지합니다.
- DVWAAdapter 등에서 생성한 인증 세션을 PluginContext를 통해 공유합니다.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple
from uuid import uuid4

from s2n.s2nscanner.crawler import crawl_recursive
from s2n.s2nscanner.http.client import HttpClient
from s2n.s2nscanner.interfaces import (
    Finding,
    PluginContext,
    PluginError,
    PluginResult,
    PluginStatus,
    Severity,
)
from .oscommand_utils import (
    build_attack_url,
    extract_params,
    match_pattern,
)

logger = logging.getLogger("s2n.plugins.oscommand")

# 기본 페이로드 / 패턴 / 파라미터 후보
DEFAULT_PAYLOADS: Sequence[str] = [
    ";id",
    "&&id",
    "|id",
    ";whoami",
    "|whoami",
    ";cat /etc/passwd",
    "|uname -a",
    "&echo vulnerable",
]

DEFAULT_PATTERNS: Sequence[str] = [
    r"uid=\d+",
    r"gid=\d+",
    r"root:.*:0:0:",
    r"administrator",
    r"vulnerable",
    r"linux",
    r"ubuntu",
]

COMMON_PARAMS: Sequence[str] = [
    "id",
    "cmd",
    "ip",
    "input",
    "search",
    "q",
    "page",
    "file",
]

class OSCommandPlugin:
    """Detects OS command injection by crawling targets and replaying payloads."""
    name = "oscommand"
    description = "Detects OS Command Injection vulnerabilities"

    def __init__(self, config: Optional[Dict[str, object]] = None):
        self.config = config or {}
        self.depth = int(self.config.get("depth", 2))
        self.timeout = int(self.config.get("timeout", 5))
        self.payloads: Sequence[str] = self.config.get("payloads", DEFAULT_PAYLOADS)
        self.patterns: Sequence[str] = self.config.get("patterns", DEFAULT_PATTERNS)
        self.http: Optional[HttpClient] = None

    # New plugin API (PluginContext -> PluginResult)
    def run(self, plugin_context: PluginContext) -> PluginResult:
        """Execute the plugin using the modern PluginContext → PluginResult API."""
        start_time = datetime.utcnow()
        findings: List[Finding] = []
        requests_sent = 0
        urls_scanned = 0

        try:
            client = self._resolve_client(plugin_context)
            target_url = self._resolve_target_url(plugin_context)
            depth = self._resolve_depth(plugin_context)

            findings, requests_sent, urls_scanned = self._scan_urls(
                client=client,
                base_url=target_url,
                depth=depth,
            )

            end_time = datetime.utcnow()
            status = PluginStatus.SUCCESS
            return PluginResult(
                plugin_name=self.name,
                status=status,
                findings=findings,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                urls_scanned=urls_scanned,
                requests_sent=requests_sent,
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("OSCommand plugin failed: %s", exc)
            end_time = datetime.utcnow()
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILED,
                findings=findings,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                error=PluginError(
                    error_type=type(exc).__name__,
                    message=str(exc),
                    traceback=None,
                ),
            )

    # Legacy API (initialize/scan/teardown) for backward compatibility
    def initialize(self, cfg=None, http: Optional[HttpClient] = None):
        """Maintain compatibility with the legacy initialize signature."""
        self.http = http or HttpClient()
        if isinstance(cfg, dict):
            self.depth = int(cfg.get("depth", self.depth))
            self.timeout = int(cfg.get("timeout", self.timeout))
        logger.info("OSCommand Plugin initialized (depth=%d, timeout=%d)", self.depth, self.timeout)

    def scan(self, base_url: str, http: Optional[HttpClient] = None) -> List[Finding]:
        """Legacy entry point that returns a plain Finding list for a base URL."""
        client = http or self.http or HttpClient()
        findings, _, _ = self._scan_urls(client=client, base_url=base_url, depth=self.depth)
        return findings

    def teardown(self):
        """Release any per-run resources held by the plugin."""
        logger.debug("OSCommand Plugin teardown complete.")

    # Internal helpers
    def _resolve_client(self, plugin_context: PluginContext) -> HttpClient:
        scan_ctx = getattr(plugin_context, "scan_context", None)

        # auth_adapter가 제공되면 해당 세션을 우선 사용
        adapter = getattr(scan_ctx, "auth_adapter", None)
        if adapter and hasattr(adapter, "get_client"):
            return adapter.get_client()

        http_client = getattr(scan_ctx, "http_client", None)
        if http_client:
            return http_client

        # fallback: initialize에서 받은 http 또는 새 HttpClient
        if self.http:
            return self.http

        return HttpClient()

    def _resolve_target_url(self, plugin_context: PluginContext) -> str:
        scan_ctx = getattr(plugin_context, "scan_context", None)
        if scan_ctx:
            config = getattr(scan_ctx, "config", None)
            if config and getattr(config, "target_url", None):
                return config.target_url.rstrip("/")

            target_url = getattr(scan_ctx, "target_url", None)
            if target_url:
                return str(target_url).rstrip("/")

        raise ValueError("ScanContext에 target_url 정보가 없습니다.")

    def _resolve_depth(self, plugin_context: PluginContext) -> int:
        depth = self.depth
        plugin_cfg = getattr(plugin_context, "plugin_config", None)
        if plugin_cfg and getattr(plugin_cfg, "custom_params", None):
            depth = int(plugin_cfg.custom_params.get("depth", depth))
        return depth

    def _scan_urls(self, client: HttpClient, base_url: str, depth: int) -> Tuple[List[Finding], int, int]:
        """
        대상 URL들을 순회하며 취약점을 탐지합니다.
        Returns: findings, requests_sent, urls_scanned
        """
        targets = crawl_recursive(base_url, client, depth=depth, timeout=self.timeout) or [base_url]
        findings: List[Finding] = []
        requests_sent = 0

        for target in targets:
            try:
                resp = client.get(target, timeout=self.timeout)
                requests_sent += 1
                html = resp.text or ""
            except Exception as exc:  # pylint: disable=broad-except
                logger.debug("Failed to crawl %s: %s", target, exc)
                continue

            params = extract_params(html, target, COMMON_PARAMS)
            new_findings, new_requests = self._test_os_command_injection(
                target=target,
                params=params,
                client=client,
            )
            findings.extend(new_findings)
            requests_sent += new_requests

        return findings, requests_sent, len(targets)

    def _test_os_command_injection(
        self,
        target: str,
        params: Sequence[str],
        client: HttpClient,
    ) -> Tuple[List[Finding], int]:
        """
        개별 URL과 파라미터에 대해 OS Command Injection을 테스트합니다.
        """
        findings: List[Finding] = []
        requests_sent = 0
        candidates = params or COMMON_PARAMS

        for param in candidates:
            vulnerable = False
            for payload in self.payloads:
                attack_url = build_attack_url(target, param, payload)
                try:
                    response = client.get(attack_url, timeout=self.timeout)
                    requests_sent += 1
                    body = (response.text or "").lower()
                except Exception as exc:  # pylint: disable=broad-except
                    logger.debug("Payload request failed (%s=%s): %s", param, payload, exc)
                    continue

                matched_pattern = match_pattern(body, self.patterns)
                if matched_pattern:
                    findings.append(
                        Finding(
                            id=f"oscmd-{uuid4().hex[:8]}",
                            plugin=self.name,
                            severity=Severity.HIGH,
                            title="OS Command Injection",
                            description=f"Parameter '{param}' appears vulnerable to OS command injection.",
                            url=attack_url,
                            parameter=param,
                            method="GET",
                            payload=payload,
                            evidence=f"Matched pattern '{matched_pattern}'",
                            timestamp=datetime.utcnow(),
                        )
                    )
                    vulnerable = True
                    break  # 동일 파라미터에 대해 추가 payload 테스트 중단

            if vulnerable:
                continue

        return findings, requests_sent

def main(config: Optional[Dict[str, object]] = None) -> OSCommandPlugin:
    """Factory exported via __all__ so the scanner can instantiate the plugin."""
    return OSCommandPlugin(config)
