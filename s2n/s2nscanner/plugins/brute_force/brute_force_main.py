import logging
from datetime import datetime
from typing import List, Any, Optional, Dict

# S2N 인터페이스 및 데이터 구조 임포트
from s2n.s2nscanner.interfaces import (
    PluginContext, PluginResult, PluginStatus,
    Finding, Severity, Confidence, PluginError,
    PluginConfig
)

# 내부 모듈 임포트
from .brute_force_cache import initialize_password_list
from .brute_force_selenium import setup_driver, scan_brute_force_with_selenium
from .brute_force_dvwa_helper import perform_dvwa_login_and_setup
from .brute_force_crawling import url as crawl_url


def _create_brute_force_finding(url: str, user: str, password: str) -> Finding:
    return Finding(
        id="brute-force-001",
        plugin="brute_force",
        severity=Severity.HIGH,
        title="무차별 대입 공격 성공 (Brute Force Success)",
        description=f"사전 공격을 통해 인증에 성공했습니다. ID: '{user}', 비밀번호: '{password}'",
        url=url,
        parameter="password/username",
        payload=f"Username: {user}, Password: {password}",
        confidence=Confidence.FIRM,
        timestamp=datetime.now().isoformat()
    )


class BruteForcePlugin:

    # config를 받을 수 있도록 __init__ 메서드 추가
    def __init__(self, config: Any = None):
        # config 타입을 PluginConfig 대신 Any로 받아 유연성을 확보합니다.
        self.config = config

    def run(self, plugin_context: PluginContext) -> PluginResult:
        # S2N 플러그인의 메인 실행 로직.
        logger = plugin_context.logger
        target_url = plugin_context.scan_context.config.target_url
        start_time = datetime.now()
        requests_sent = 0
        findings: List[Finding] = []
        error: Optional[PluginError] = None

        logger.info("--- 🛡️ Brute Force (무차별 대입) 탐지 스캐너 시작 ---")

        # 1. 대상 URL 유효성 검사
        if not target_url or not target_url.startswith('http'):
            message = "대상 URL이 'http' 또는 'https'로 시작하지 않아 스캔을 중단합니다."
            logger.error(message)
            return PluginResult(
                plugin_name=plugin_context.plugin_name,
                status=PluginStatus.FAILED,
                start_time=start_time,
                end_time=datetime.now(),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
                requests_sent=requests_sent,
                error=PluginError(message=message, timestamp=datetime.now())
            )

        # 2. 비밀번호 목록 초기화 (로거 전달)
        try:
            PASSWORD_LIST = initialize_password_list(logger)
            if not PASSWORD_LIST:
                raise ValueError("유효한 사전 공격 목록을 확보하지 못했습니다.")
        except Exception as e:
            message = f"비밀번호 목록 초기화 실패: {type(e).__name__} - {e}"
            logger.error(message)
            return PluginResult(
                plugin_name=plugin_context.plugin_name,
                status=PluginStatus.FAILED,
                start_time=start_time,
                end_time=datetime.now(),
                duration_seconds=(datetime.now() - start_time).total_seconds(),
                requests_sent=requests_sent,
                error=PluginError(message=message, timestamp=datetime.now())
            )

        # 3. 비밀번호 목록 일부 출력
        passwords_to_attempt = PASSWORD_LIST[:20]
        logger.info(f"[+] 크롤링된 사전 공격 목록 ({len(PASSWORD_LIST)}개 중 20개 시도)")

        for idx, passwd in enumerate(passwords_to_attempt[:7]):
            logger.debug(f"  {idx + 1}위: {passwd}")
        logger.info(f"비밀번호 출처: {crawl_url}")

        # 4. 스캔 실행
        driver = None
        try:
            driver = setup_driver(logger)

            is_dvwa = "/dvwa/" in target_url.lower()

            if is_dvwa:
                success, _ = perform_dvwa_login_and_setup(driver, target_url, logger)
                if not success:
                    raise Exception("DVWA 초기 설정(관리자 로그인/보안 레벨 설정) 실패")

            success_details: Optional[Dict[str, str]] = scan_brute_force_with_selenium(
                driver, target_url, passwords_to_attempt, is_dvwa, logger
            )

            if success_details:
                user = success_details['user']
                password = success_details['password']
                findings.append(_create_brute_force_finding(target_url, user, password))
                logger.critical(f"🚨🚨 Brute Force 취약점 발견: ID='{user}', PW='{password}'")
            else:
                logger.info("🎉 Brute Force 취약점 징후가 발견되지 않았습니다.")

        except Exception as e:
            message = f"스캔 중 최종 오류 발생: {type(e).__name__} - {e}"
            logger.error(message, exc_info=True)
            error = PluginError(message=message, timestamp=datetime.now())
        finally:
            if driver:
                driver.quit()

        # 5. 결과 반환 (PluginResult)
        status = PluginStatus.SUCCESS
        if error:
            status = PluginStatus.FAILED if not findings else PluginStatus.PARTIAL

        end_time = datetime.now()
        return PluginResult(
            plugin_name=plugin_context.plugin_name,
            status=status,
            findings=findings,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=(end_time - start_time).total_seconds(),
            requests_sent=requests_sent,
            error=error
        )


# main 함수 사용
def main(config=None):
    return BruteForcePlugin(config)
