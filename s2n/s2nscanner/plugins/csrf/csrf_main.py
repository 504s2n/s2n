import logging
from datetime import datetime
from typing import List

# 패키지 실행과 직접 실행을 모두 지원하기 위한 import 처리
from s2n.s2nscanner.interfaces import (
    Finding,
    PluginConfig,
    PluginContext,
    PluginError,
    PluginResult,
    PluginStatus,
)
from s2n.s2nscanner.plugins.csrf.csrf_scan import csrf_scan

# 전용 로거
logger = logging.getLogger("s2n.plugins.csrf")


# ======= CSRF 스캐너 기능 개발부 =========

# 메인 플러그인 스캐너 클래스 정의입니다.
class CSRFScanner:
    """CSRF 취약점 스캐너"""
    name = "csrf"
    description = "CSRF scanner plugin from s2n.s2nscanner"

    #  CSRF Plugin의 설정 파라미터입니다.
    def __init__(self, config: PluginConfig | None = None):
        self.config = config or {}

    # CSRFScanner.run(플러그인_컨텍스트)로 플러그인을 실행합니다.
    def run(self, plugin_context: PluginContext) -> PluginResult | PluginError:  # 【변경됨】
        start_time = datetime.now()
        findings: List[Finding] = []
        # 나중에 타입 확인 
        client = plugin_context.scan_context.http_client
        # 이 url 목록을 차례대로 or 병렬로 scan() 함수에 적용한다.
        target_urls = plugin_context.target_urls

        try:
            # for 문이든 뭐든 써서,  target_urls로 개별 url 스캔 수행하게 만들기

            for url in target_urls:
                scan_result = csrf_scan(url, http_client=client, plugin_context=plugin_context)
                findings.extend(scan_result)

        except Exception as e:
            logger.exception("[CSRFScanner.run] plugin error: %s", e)
            return PluginError(
                error_type=type(e).__name__,
                message=str(e),
                traceback=str(e.__traceback__)
            )

        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.PARTIAL if findings else PluginStatus.SUCCESS,
            findings=findings,
            start_time=start_time,
            end_time=datetime.now(),
            duration_seconds=(datetime.now() - start_time).total_seconds(),
            urls_scanned=1,
            requests_sent=1
        )


# 메인 함수
def main(config: None | PluginConfig = None):
    return CSRFScanner(config)


# 이 파일을 직접 실행할 때 main()을 호출
if __name__ == "__main__":
    main()
