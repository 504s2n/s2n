from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional

from s2n.s2nscanner.interfaces import (
    Finding,
    PluginConfig,
    PluginContext,
    PluginError,
    PluginResult,
    PluginStatus,
)

from .xss_scanner import ReflectedScanner
from s2n.s2nscanner.logger import get_logger


logger = get_logger("plugins.xss")


# 페이로드 파일 로드
def _load_payload_path() -> Path:
    payload_name = "xss_payloads.json"
    script_path = Path(__file__).parent / payload_name
    if script_path.exists():
        return script_path
    raise FileNotFoundError(f"Payload file not found: {payload_name}")


# XSS 취약점 스캐너
class XSSScanner:
    name = "xss"
    description = "Detects Reflected/Stored Cross-Site Scripting vulnerabilities."

    def __init__(self, config: PluginConfig | None = None):
        """Initialize XSS scanner with optional config"""
        self.config = config or {}
        # payload_path: config에서 가져오거나 기본 경로에서 자동 검색
        payload_file = getattr(self.config, "payload_path", None)
        self.payload_path = Path(payload_file) if payload_file else _load_payload_path()

    def _build_scanner(self, http_client: Optional[Any] = None) -> ReflectedScanner:
        """Build ReflectedScanner instance with shared http_client"""
        if http_client is None:
            raise ValueError(
                "XSSScanner requires scan_context.http_client to be provided."
            )
        return ReflectedScanner(self.payload_path, http_client=http_client)

    def run(self, plugin_context: PluginContext) -> PluginResult | PluginError:
        """Execute XSS scan and return results"""
        start_time = datetime.now()
        findings: List[Finding] = []

        # 스캔 실행에 필요한 데이터 추출
        http_client = plugin_context.scan_context.http_client
        target_urls = plugin_context.target_urls or []

        # 스캐너 생성 및 실행
        try:
            scanner = self._build_scanner(http_client=http_client)
            result = scanner.run(plugin_context)
            findings = getattr(result, "findings", [])

        # 에러 발생 시 PluginError 반환
        except Exception as e:
            logger.exception("[XSSScanner.run] plugin error: %s", e)
            return PluginError(
                error_type=type(e).__name__,
                message=str(e),
                traceback=str(e.__traceback__),
            )

        # 결과 래핑
        end_time = datetime.now()
        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.PARTIAL if findings else PluginStatus.SUCCESS,
            findings=findings,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=(end_time - start_time).total_seconds(),
            urls_scanned=getattr(result, "urls_scanned", len(target_urls)),
            requests_sent=getattr(result, "requests_sent", 1),
        )


# 플러그인 팩토리 함수
def main(config: None | PluginConfig = None):
    """Factory function to create XSSScanner instance"""
    return XSSScanner(config)


if __name__ == "__main__":
    main()
