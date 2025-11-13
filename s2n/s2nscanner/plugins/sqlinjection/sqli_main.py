import logging
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
import traceback

# 외부 라이브러리
import requests
from bs4 import BeautifulSoup
import requests.compat


# # 패키지 실행과 직접 실행을 모두 지원하기 위한 import 처리

# 프레임워크 인터페이스 (이미지 및 학습된 표준 반영)
from s2n.s2nscanner.interfaces import (
    Confidence,
    Finding,
    HTTPRequest,
    PluginConfig,
    PluginContext,
    PluginError,
    PluginResult,
    PluginStatus,
    ScanConfig,
    ScanContext,
    ScannerConfig,
    Severity,
)

# HTTP 클라이언트 (별도 모듈)
from s2n.s2nscanner.http.client import HttpClient

# 모듈 임포트 (상대 경로 사용)
from .sqli_config import TEST_PAYLOAD, TEST_PAYLOAD_TIME_BLIND, TIME_THRESHOLD
from .sqli_dvwa_helper import (
    check_for_success_indicator, check_for_error_indicator,
    extract_url_info
)

logger = logging.getLogger('s2n.plugins.sqlinjection')

class SQLInjectionPlugin:
    name = "sqlinjection"
    description = "SQL Injection 취약점을 스캐너"

    _finding_id_counter = 0

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    def _get_new_finding_id(self):
        SQLInjectionPlugin._finding_id_counter += 1
        return f"{self.name}-{self._finding_id_counter}"

    def _create_finding(self, vul_type: str, severity: Severity, url: str, payload: Optional[str], method: str,
                        param: str, details: str) -> Finding:
        title_map = {
            "SQL Injection (Data Retrieval/Boolean)": "SQL Injection (Data Exposure)",
            "SQL Injection (Error Based)": "SQL Injection (Error Message)",
            "SQL Injection (Time Based)": "SQL Injection (Blind)"
        }

        # Finding 구조에 method와 parameter를 추가
        return Finding(
            id=self._get_new_finding_id(),
            plugin=self.name,
            severity=severity,
            title=title_map.get(vul_type, "SQL Injection Detected"),
            description=f"URL: {url}에서 {method} 요청의 파라미터 '{param}'에서 {vul_type} 징후가 발견되었습니다. 상세: {details}",
            url=url,
            method=method,
            parameter=param,
            payload=payload if payload else None,
            evidence=details
        )


    # 플러그인 표준 실행 함수 (run)

    def run(self, context: PluginContext) -> PluginResult:

        start_dt = datetime.now()
        findings: List[Finding] = []
        requests_sent = 0

        try:
            target = context.scan_context.target_url
        except AttributeError:
            target = ""

        # 1. 클라이언트 설정 (ScanContext 내부 접근)
        try:
            # auth_adapter는 auth_config에서 가져온다고 가정
            auth_adapter = context.scan_context.auth_config.auth_adapter

            # 인증 여부에 따라 클라이언트 획득 방식 변경
            if auth_adapter:
                client = auth_adapter.get_client()
            else:
                client = context.scan_context.http_client
        except AttributeError as e:
            # 필수 컨텍스트 필드 누락 오류 보고
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILED,
                error=self._create_plugin_error(f"컨텍스트 필드 접근 오류: {e}"),
                duration_seconds=(datetime.now() - start_dt).total_seconds()
            )

        # URL 파싱
        try:
            base_url, get_params_from_url = extract_url_info(target)
        except Exception as e:
            logger.error(f"URL 파싱 오류: {e}")
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILED,
                error=self._create_plugin_error(f"URL 파싱 중 오류 발생: {e}"),
                duration_seconds=(datetime.now() - start_dt).total_seconds()
            )

        # 2. GET 파라미터 스캔 및 폼 필드 스캔
        get_findings, get_requests = self._scan_get_param(client, base_url, target, get_params_from_url)
        findings.extend(get_findings)
        requests_sent += get_requests

        form_findings, form_requests = self._scan_forms(client, target)
        findings.extend(form_findings)
        requests_sent += form_requests

        # 3. 결과 반환 (PluginResult 표준)
        status = PluginStatus.PARTIAL if not findings else PluginStatus.SUCCESS

        return PluginResult(
            plugin_name=self.name,
            status=status,
            findings=findings,
            duration_seconds=(datetime.now() - start_dt).total_seconds(),
            requests_sent=requests_sent  # 요청 수 보고
        )

    def _create_plugin_error(self, message: str) -> PluginError:

        return PluginError(
            error_type="PluginError",
            message=message,
            timestamp=datetime.now(),
            traceback=traceback.format_exc()
        )

    # 스캔 로직: GET 파라미터

    def _scan_get_param(self, client: requests.Session, base_url: str, full_url: str, param_names: List[str]) -> tuple[
        List[Finding], int]:

        vulnerabilities = []
        requests_sent = 0
        success_payload = "' OR 1=1 -- "

        for param in param_names:
            # 1. 성공/에러 기반 탐지
            attack_url = f"{base_url}?{param}=1{success_payload}"
            try:
                response = client.get(attack_url, timeout=5)
                requests_sent += 1
            except requests.exceptions.RequestException as e:
                logger.debug(f"GET 요청 오류 ({param}): {e}")
                continue

            success_indicator = check_for_success_indicator(response.text)
            error_indicator = check_for_error_indicator(response.text)

            if success_indicator:
                vulnerabilities.append(self._create_finding(
                    "SQL Injection (Data Retrieval/Boolean)", Severity.HIGH, full_url,
                    success_payload, "GET", param,
                    f"성공 징후 '{success_indicator}' 발견"
                ))
                continue

            if error_indicator:
                vulnerabilities.append(self._create_finding(
                    "SQL Injection (Error Based)", Severity.HIGH, full_url,
                    success_payload, "GET", param,
                    f"에러 키워드 '{error_indicator}' 발견"
                ))
                continue

            # 2. 시간 기반 블라인드 탐지
            attack_url_time = f"{base_url}?{param}=1{TEST_PAYLOAD_TIME_BLIND}"
            try:
                start_time = time.time()
                client.get(attack_url_time, timeout=10)
                requests_sent += 1
                elapsed_time = time.time() - start_time

                if elapsed_time > TIME_THRESHOLD:
                    vulnerabilities.append(self._create_finding(
                        "SQL Injection (Time Based)", Severity.MEDIUM, full_url,
                        TEST_PAYLOAD_TIME_BLIND, "GET", param,
                        f"응답 시간 {elapsed_time:.2f}초 초과"
                    ))
            except (requests.exceptions.Timeout, requests.exceptions.RequestException) as e:
                logger.debug(f"GET (Time Blind) 요청 오류 ({param}): {e}")
                pass

        return vulnerabilities, requests_sent

    # 스캔 로직: Form 처리

    def _scan_forms(self, client: requests.Session, url: str) -> tuple[List[Finding], int]:
        vulnerabilities = []
        requests_sent = 0

        try:
            response = client.get(url, timeout=5)
            requests_sent += 1
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
        except requests.exceptions.RequestException as e:
            logger.debug(f"폼 페이지 요청 오류: {e}")
            return [], requests_sent

        for form in forms:
            method = form.get('method', 'GET').upper()
            form_url = requests.compat.urljoin(url, form.get('action', url))
            input_fields = form.find_all(['input', 'textarea', 'select'])
            param_names = [field.get('name') for field in input_fields if field.get('name')]

            if not param_names: continue

            for param in param_names:
                # 1. 에러 기반 탐지
                test_data_error = {p: f"1{TEST_PAYLOAD}" if p == param else "1" for p in param_names}
                req_func = client.post if method == 'POST' else client.get

                try:
                    res = req_func(form_url,
                                   data=test_data_error if method == 'POST' else None,
                                   params=test_data_error if method == 'GET' else None,
                                   timeout=5, allow_redirects=True)
                    requests_sent += 1
                except requests.exceptions.RequestException as e:
                    logger.debug(f"폼 요청 오류 ({method}/{param}): {e}")
                    continue

                error_indicator = check_for_error_indicator(res.text)
                if error_indicator:
                    vulnerabilities.append(self._create_finding(
                        "SQL Injection (Error Based)", Severity.HIGH, form_url,
                        f"1{TEST_PAYLOAD}", method, param,
                        f"에러 키워드 '{error_indicator}' 발견"
                    ))
                    continue

                # 2. 시간 기반 블라인드 탐지
                test_data_time = {p: f"1{TEST_PAYLOAD_TIME_BLIND}" if p == param else "1" for p in param_names}
                try:
                    start_time = time.time()
                    req_func(form_url,
                             data=test_data_time if method == 'POST' else None,
                             params=test_data_time if method == 'GET' else None,
                             timeout=10, allow_redirects=True)
                    requests_sent += 1
                    elapsed_time = time.time() - start_time

                    if elapsed_time > TIME_THRESHOLD:
                        vulnerabilities.append(self._create_finding(
                            "SQL Injection (Time Based)", Severity.MEDIUM, form_url,
                            TEST_PAYLOAD_TIME_BLIND, method, param,
                            f"응답 시간 {elapsed_time:.2f}초 초과"
                        ))
                except (requests.exceptions.Timeout, requests.exceptions.RequestException) as e:
                    logger.debug(f"폼 (Time Blind) 요청 오류 ({method}/{param}): {e}")
                    pass

        return vulnerabilities, requests_sent

# 메인 함수
def main(config=None):
    return SQLInjectionPlugin(config)
