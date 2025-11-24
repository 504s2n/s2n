"""HTTP Response Headers 보안 통합 테스트

이 파일은 HTTP 응답 헤더 보안 검사 기능을 통합적으로 테스트합니다.
주로 CSRF 보호 헤더(X-Frame-Options, Content-Security-Policy, SameSite 등)를
검증하는 scan_res_headers 함수와 전체 CSRF 스캔 플로우를 테스트합니다.

통합 테스트 원칙:
1. MockHTTPClient, MockRequest, MockResponse 사용 (외부 패키지 사용 금지)
2. 실제 HTTP 요청 없이 전체 플로우 검증
3. 다양한 헤더 조합 시나리오 테스트
"""

import pytest
from test.mock_data import MockHTTPClient, MockRequest, MockResponse, MockPluginContext
from s2n.s2nscanner.plugins.csrf.csrf_scan import scan_res_headers, csrf_scan
from s2n.s2nscanner.interfaces import Severity


@pytest.mark.integration
def test_scan_res_headers_all_missing():
    """모든 보안 헤더가 없는 경우 - MEDIUM severity"""
    headers = {}

    result = scan_res_headers(headers)

    assert result.plugin == "csrf"
    assert result.severity == Severity.MEDIUM
    assert "CSRF Protection Headers Issues" in result.title
    assert "X-Frame-Options" in result.evidence
    assert "Content-Security-Policy" in result.evidence
    assert result.cwe_id == "CWE-352"
    assert result.cvss_score == 5.0


@pytest.mark.integration
def test_scan_res_headers_all_present():
    """모든 보안 헤더가 존재하는 경우 - INFO severity"""
    headers = {
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "SameSite": "Strict",
    }

    result = scan_res_headers(headers)

    assert result.plugin == "csrf"
    assert result.severity == Severity.INFO
    assert "All CSRF Protection Headers Present" in result.title
    assert result.cwe_id is None
    assert result.cvss_score is None


@pytest.mark.integration
def test_scan_res_headers_partial():
    """일부 보안 헤더만 존재하는 경우"""
    headers = {
        "X-Frame-Options": "SAMEORIGIN"
        # Content-Security-Policy 누락
    }

    result = scan_res_headers(headers)

    assert result.severity == Severity.MEDIUM
    assert "CSRF Protection Headers Issues" in result.title
    assert "Content-Security-Policy" in result.evidence
    assert (
        "X-Frame-Options" not in result.evidence
    )  # 이미 존재하므로 누락 목록에 없어야 함


@pytest.mark.integration
def test_scan_res_headers_case_sensitivity():
    """헤더 이름의 대소문자 구분 테스트"""
    # HTTP 헤더는 대소문자를 구분하지 않지만, 딕셔너리 키는 구분함
    headers = {
        "x-frame-options": "DENY",  # 소문자
        "content-security-policy": "default-src 'self'",  # 소문자
    }

    result = scan_res_headers(headers)

    # 현재 구현은 대소문자를 구분하므로 누락으로 판단됨
    assert result.severity == Severity.MEDIUM
    assert "CSRF Protection Headers Issues" in result.title


@pytest.mark.integration
def test_scan_res_headers_extra_headers():
    """필수 헤더 외에 추가 보안 헤더가 있는 경우"""
    headers = {
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "SameSite": "Strict",
        "X-Content-Type-Options": "nosniff",  # 추가 헤더
        "Strict-Transport-Security": "max-age=31536000",  # 추가 헤더
        "X-XSS-Protection": "1; mode=block",  # 추가 헤더
    }

    result = scan_res_headers(headers)

    # 필수 헤더가 모두 있으므로 INFO
    assert result.severity == Severity.INFO
    assert "All CSRF Protection Headers Present" in result.title


@pytest.mark.integration
def test_csrf_scan_integration_with_missing_headers():
    """csrf_scan 전체 플로우 - 보안 헤더 누락 시나리오"""

    # MockResponse를 반환하는 MockSession 설정
    class CustomMockSession:
        def __init__(self):
            self.headers = {"User-Agent": "test"}

        def get(self, url, timeout=10):
            # 보안 헤더가 없는 응답
            response = MockResponse(
                text="<html><body><form><input name='csrf_token' /></form></body></html>"
            )
            response.headers = {}  # 보안 헤더 없음
            return response

    # MockHTTPClient에 커스텀 세션 설정
    http_client = MockHTTPClient()
    http_client.s = CustomMockSession()

    target_url = "http://example.com/test"
    results = csrf_scan(target_url, http_client=http_client, plugin_context=None)

    # csrf_scan은 3개의 Finding을 반환: html_result, http_result, html_form_result
    assert isinstance(results, list)
    assert len(results) == 3

    # http_result (scan_res_headers의 결과) 검증
    http_result = results[1]  # 두 번째 항목이 scan_res_headers의 결과
    assert http_result.severity == Severity.MEDIUM
    assert "CSRF Protection Headers Issues" in http_result.title


@pytest.mark.integration
def test_csrf_scan_integration_with_all_headers():
    """csrf_scan 전체 플로우 - 모든 보안 헤더 존재 시나리오"""

    class CustomMockSession:
        def __init__(self):
            self.headers = {"User-Agent": "test"}

        def get(self, url, timeout=10):
            # 모든 보안 헤더가 있는 응답
            response = MockResponse(
                text="<html><body><form><input name='csrf_token' /></form></body></html>"
            )
            response.headers = {
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'",
                "SameSite": "Strict",
            }
            return response

    http_client = MockHTTPClient()
    http_client.s = CustomMockSession()

    target_url = "http://example.com/secure"
    results = csrf_scan(target_url, http_client=http_client, plugin_context=None)

    assert isinstance(results, list)
    assert len(results) == 3

    # http_result 검증
    http_result = results[1]
    assert http_result.severity == Severity.INFO
    assert "All CSRF Protection Headers Present" in http_result.title


@pytest.mark.integration
def test_csrf_scan_with_plugin_context():
    """PluginContext를 사용한 csrf_scan 통합 테스트"""
    # MockPluginContext 생성
    target_url = "http://example.com/api"
    context = MockPluginContext(obj={"target_urls": [target_url]})

    class CustomMockSession:
        def __init__(self):
            self.headers = {"User-Agent": "s2n_csrf/1.0"}

        def get(self, url, timeout=10):
            response = MockResponse(
                text="<html><body><p>API Endpoint</p></body></html>"
            )
            response.headers = {
                "Content-Security-Policy": "default-src 'self'"
                # X-Frame-Options 누락
            }
            return response

    http_client = MockHTTPClient()
    http_client.s = CustomMockSession()

    results = csrf_scan(target_url, http_client=http_client, plugin_context=context)

    assert isinstance(results, list)
    assert len(results) == 3

    # 부분적으로 헤더가 누락된 경우
    http_result = results[1]
    assert http_result.severity == Severity.MEDIUM
    assert "X-Frame-Options" in http_result.evidence


@pytest.mark.integration
def test_multiple_urls_header_scanning():
    """여러 URL에 대한 헤더 스캔 시뮬레이션"""
    test_cases = [
        {
            "url": "http://example.com/page1",
            "headers": {},
            "expected_severity": Severity.MEDIUM,
        },
        {
            "url": "http://example.com/page2",
            "headers": {
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'self'",
                "SameSite": "Lax",
            },
            "expected_severity": Severity.INFO,
        },
        {
            "url": "http://example.com/page3",
            "headers": {"X-Frame-Options": "SAMEORIGIN"},
            "expected_severity": Severity.MEDIUM,
        },
    ]

    results = []
    for test_case in test_cases:
        result = scan_res_headers(test_case["headers"])
        results.append({"url": test_case["url"], "result": result})

    # 각 결과 검증
    assert results[0]["result"].severity == Severity.MEDIUM
    assert results[1]["result"].severity == Severity.INFO
    assert results[2]["result"].severity == Severity.MEDIUM

    # 총 3개의 URL 스캔 완료
    assert len(results) == 3


@pytest.mark.integration
def test_header_values_with_different_policies():
    """다양한 헤더 정책 값 테스트"""
    test_scenarios = [
        {
            "name": "DENY policy",
            "headers": {
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'none'",
            },
            "expected": Severity.INFO,
        },
        {
            "name": "SAMEORIGIN policy with unsafe-inline",
            "headers": {
                "X-Frame-Options": "SAMEORIGIN",
                "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
            },
            "expected": Severity.MEDIUM,  # CSP contains unsafe directive
        },
        {
            "name": "Empty CSP value",
            "headers": {
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "",  # 빈 값
            },
            "expected": Severity.INFO,  # 헤더가 존재하고 빈 값은 문제 없음
        },
    ]

    for scenario in test_scenarios:
        result = scan_res_headers(scenario["headers"])
        assert result.severity == scenario["expected"], f"Failed for {scenario['name']}"


@pytest.mark.integration
def test_csrf_scan_error_handling():
    """csrf_scan의 예외 처리 테스트"""

    # 잘못된 세션을 가진 http_client
    class BrokenMockSession:
        def __init__(self):
            self.headers = {}

        def get(self, url, timeout=10):
            raise Exception("Network error simulated")

    http_client = MockHTTPClient()
    http_client.s = BrokenMockSession()

    target_url = "http://example.com/broken"
    results = csrf_scan(target_url, http_client=http_client, plugin_context=None)

    # 예외 발생 시 빈 리스트 반환
    assert isinstance(results, list)
    assert len(results) == 0


@pytest.mark.integration
def test_headers_with_unicode_and_special_chars():
    """유니코드 및 특수 문자가 포함된 헤더 테스트"""
    headers = {
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'; script-src https://cdn.example.com",
        "SameSite": "Strict; 한글=테스트",  # 특수 케이스
    }

    result = scan_res_headers(headers)

    # 모든 필수 헤더가 존재
    assert result.severity == Severity.INFO


@pytest.mark.integration
def test_scan_res_headers_remediation_and_references():
    """결과 객체의 remediation과 references 필드 검증"""
    # 헤더 누락 케이스
    result_missing = scan_res_headers({})

    assert result_missing.remediation is not None
    assert "CSRF protection headers" in result_missing.remediation
    assert len(result_missing.references) > 0
    assert any("owasp.org" in ref for ref in result_missing.references)

    # 헤더 존재 케이스
    result_present = scan_res_headers(
        {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "SameSite": "Strict",
        }
    )

    assert result_present.remediation is None
    assert len(result_present.references) > 0
