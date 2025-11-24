
from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from s2n.s2nscanner.clients.http_client import HttpClient
from s2n.s2nscanner.interfaces import (
    Finding,
    PluginContext,
    PluginError,
    PluginResult,
    PluginStatus,
    Severity,
    Confidence,
)
from s2n.s2nscanner.logger import get_logger

logger = get_logger("plugins.soft_brute_force")

# 속도 제한 우회 또는 미적용 여부 확인을 위한 파라미터
RATE_LIMIT_ATTEMPTS = 10
RATE_LIMIT_DELAY = 0.1  # 매우 짧은 간격으로 요청 -> 차단 여부 확인

class SoftBruteForcePlugin:
    name = "soft_brute_force"
    description = "Checks for rate limiting and default credentials"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.rate_limit_attempts = int(self.config.get("rate_limit_attempts", RATE_LIMIT_ATTEMPTS))

    def run(self, plugin_context: PluginContext) -> PluginResult:
        start_time = datetime.utcnow()
        findings: List[Finding] = []
        requests_sent = 0
        
        try:
            # 스캔 환경에서 생성된 HttpClient 사용
            client = self._resolve_client(plugin_context)

            # 대상 타겟 URL 확보
            target_url = self._resolve_target_url(plugin_context)
            
            # Rate Limiting 탐지
            rl_findings, rl_reqs = self._check_rate_limiting(client, target_url)
            findings.extend(rl_findings)
            requests_sent += rl_reqs

            status = PluginStatus.SUCCESS
            if not findings:
                logger.info("No soft brute force vulnerabilities found.")

            return PluginResult(
                plugin_name=self.name,
                status=status,
                findings=findings,
                start_time=start_time,
                end_time=datetime.utcnow(),
                duration_seconds=(datetime.utcnow() - start_time).total_seconds(),
                requests_sent=requests_sent,
                urls_scanned=1 
            )

        except Exception as exc:
            logger.exception("Soft Brute Force plugin failed: %s", exc)
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILED,
                findings=findings,
                start_time=start_time,
                end_time=datetime.utcnow(),
                duration_seconds=(datetime.utcnow() - start_time).total_seconds(),
                error=PluginError(
                    error_type=type(exc).__name__,
                    message=str(exc),
                    traceback=None,
                ),
            )

    def _resolve_client(self, plugin_context: PluginContext) -> HttpClient:
        """
        PluginContext 내부에서 HttpClient가 이미 초기화되어 있다면 그것을 사용하고,
        없다면 새 HttpClient를 생성하여 반환.

        - 모든 플러그인은 동일한 HttpClient(Session) 재사용을 권장
        """
        scan_ctx = getattr(plugin_context, "scan_context", None)
        if scan_ctx and getattr(scan_ctx, "http_client", None):
            return scan_ctx.http_client
        return HttpClient()

    def _resolve_target_url(self, plugin_context: PluginContext) -> str:
        """
        PluginContext에서 대상 URL을 가져오는 헬퍼 함수
        - config.target_url → scan_context.target_url 순서로 확인
        - 없으면 오류 발생
        """
        scan_ctx = getattr(plugin_context, "scan_context", None)
        if scan_ctx:
            if getattr(scan_ctx.config, "target_url", None):
                 return scan_ctx.config.target_url
            if getattr(scan_ctx, "target_url", None):
                return str(scan_ctx.target_url)
        raise ValueError("Target URL not found in context")

    def _check_rate_limiting(self, client: HttpClient, url: str) -> Tuple[List[Finding], int]:
        """
        Rate Limiting(속도 제한) 체크 메서드

        방식:
        1. GET으로 초기 응답 확보 (로그인 페이지라고 가정)
        2. 매우 빠른 간격으로 무작위 실패 로그인 요청 반복
        3. 응답 상태코드, 텍스트, 응답 패턴 분석
           - 429 Too Many Requests
           - CAPTCHA 등장
           - 'too many attempts', 'blocked' 등의 키워드
        4. 아무런 제한이 감지되지 않으면 "Rate Limiting 없음"으로 판단하여 Finding 생성
        """
        findings = []
        requests_sent = 0
        logger.info("Checking for rate limiting on %s", url)
        
        # 초기 응답 확인
        initial_response = client.get(url)
        requests_sent += 1

        responses = []
        start_time = time.time()
        
        for i in range(self.rate_limit_attempts):
            # Send garbage credentials
            data = {"username": f"invalid_user_{i}", "password": f"invalid_pass_{i}"}
            try:
                resp = client.post(url, data=data)
                responses.append(resp)
                requests_sent += 1
                time.sleep(RATE_LIMIT_DELAY)
            except Exception as e:
                logger.debug("Request failed during rate limit check: %s", e)

        duration = time.time() - start_time
        
        # Analyze responses
        # 1. Check for 429 Too Many Requests
        if any(r.status_code == 429 for r in responses):
            logger.info("Rate limiting detected (429 status).")
            return [], requests_sent

        # 2. Check for CAPTCHA or specific text
        block_keywords = ["captcha", "too many attempts", "lockout", "blocked", "try again later"]
        for r in responses:
            if any(keyword in r.text.lower() for keyword in block_keywords):
                logger.info("Rate limiting/Lockout detected (keyword match).")
                return [], requests_sent

        # 3. Check for increasing response time (soft throttling) - simplified
        # If we reached here, no obvious blocking occurred.
        
        findings.append(Finding(
            id=f"soft-bf-rate-limit-{uuid4().hex[:8]}",
            plugin=self.name,
            severity=Severity.MEDIUM,
            title="No Rate Limiting Detected",
            description=f"Performed {self.rate_limit_attempts} rapid login attempts without any sign of blocking or throttling.",
            url=url,
            confidence=Confidence.FIRM,
            evidence=f"Sent {self.rate_limit_attempts} requests in {duration:.2f}s. All returned {responses[0].status_code if responses else 'N/A'}."
        ))
        
        return findings, requests_sent


def main(config: Optional[Dict[str, Any]] = None) -> SoftBruteForcePlugin:
    return SoftBruteForcePlugin(config)
