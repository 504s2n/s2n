import logging
import uuid
from typing import List, Optional, Any

from s2n.s2nscanner.http.client import HttpClient
from s2n.s2nscanner.interfaces import PluginContext, Finding, HTTPRequest, Severity, Confidence
from s2n.s2nscanner.plugins.csrf.csrf_constants import CSRF_TOKEN_KEYWORDS, USER_AGENT
from s2n.s2nscanner.plugins.csrf.csrf_utils import FormParser

logger = logging.getLogger("s2n.plugins.csrf")


# TODO:
# - CSRF Keyword CVE 등 참조하여 키워드 목록 보강 (+ 동적으로 로드하는 기능 고려)
# - 3가지 취약점 스캔 병렬 처리 (동시 수행)
# - http_res_headers 검증 로직 강화: 헤더 필드 뿐만 아니라 값 검증 추가 (예: X-Frame-Options: DENY or SAMEORIGIN 등)


def csrf_scan(
        target_url: str,
        http_client: Optional[HttpClient] = None,
        plugin_context: Optional[PluginContext] = None,
) -> List[Finding]:
    """
    지정된 URL에 대해 CSRF 취약점 검사를 수행합니다.
    실제 공격을 하지 않으며, CSRF 토큰 존재 여부 등만 점검합니다.
    Returns:
        List[Finding]: 발견된 취약점(없으면 빈 리스트)
    """
    results: List[Finding] = []

    # 로거 설정
    context_logger = getattr(plugin_context, "logger", None) or logger

    # HTTP 클라이언트 준비

    # 세션 및 헤더 설정
    session = getattr(http_client, "s", None)
    if session is None:
        context_logger.error("HTTPClient must expose an underlying session via attribute 's'.")
        return results
    if "User-Agent" not in session.headers:
        session.headers.update({"User-Agent": USER_AGENT})

    try:
        # GET 요청으로 폼 페이지 획득
        resp = session.get(target_url, timeout=10)
        # HTTP Response 메시지를 검증해야함
        # + HTTP 헤더에서 CSRF 필드를 확인해야함
        # + Form 태그가 왜 들어가야함? 
        # Form 태그 검증 자체로직이 분리되어야함. (클라이언트 / 서버 사이드 양측 검증이 필요함)
        # + 클라이언트에서 쿠키 탈취에 취약할 수 있는 코드 패턴 등 검사해야함.
        html = resp.text
        # CSRF 토큰 키워드가 HTML에 존재하는지 확인
        # scan_html로 response html text 검사 (주요 "csrf", "token" 키워드를 검색함)
        html_result = scan_html(html, resp, target_url)
        http_result = scan_res_headers(resp.headers)
        html_form_result = scan_form_tags(html, resp, target_url)
        results.extend([html_result, http_result, html_form_result])
        # Form 태그 등에서 CSRF 토큰 미존재 취약점 발견 시 결과 추가

        # Response Header 검사

    except Exception as e:
        context_logger.error(f"[csrf_scan] Error scanning {target_url}: {e}")
        return results

    return results


# HTML 텍스트에서 CSRF 토큰 존재 여부 검사
# TODO: CSRF HTTP Request/Response 헤더 검사 로직 추가 필요
# TODO: Form, Input 태그 내의 검사 로직
# TODO: 정적 검사 추가 
def scan_html(html: str, resp: Any, target_url: str, ) -> Finding:
    """
    주어진 HTML에서 CSRF 취약점을 검사합니다.
    CSRF 토큰이 발견되지 않으면 Finding 객체를 반환합니다.
    """
    # 모든 키워드 병렬(동시에) 검색: 하나라도 있으면 token_found = True
    html_lower = html.lower()
    token_found = any(keyword.lower() in html_lower for keyword in CSRF_TOKEN_KEYWORDS)

    if not token_found:
        # 취약점 발견: CSRF 토큰 미존재
        return Finding(
            id=str(uuid.uuid4()),
            plugin="csrf",
            severity=Severity.HIGH,
            title="CSRF Token Not Found",
            description="No CSRF token detected in form or page. This may expose the site to CSRF attacks.",
            url=target_url,
            parameter=None,
            method="GET",
            payload=None,
            evidence="No CSRF token keyword found in response HTML.",
            request=HTTPRequest(
                method="GET",
                url=target_url,
                headers=dict(resp.request.headers),
                body=None,
                cookies=dict(resp.request._cookies) if hasattr(resp.request, "_cookies") else {},
            ),
            response=None,
            remediation="Implement anti-CSRF tokens in all forms that perform state-changing actions.",
            references=[
                "https://owasp.org/www-community/attacks/csrf",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
            ],
            cwe_id="CWE-352",
            cvss_score=6.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            confidence=Confidence.FIRM,
        )

    # 토큰이 있으면 취약점 X informational finding (선택)
    return Finding(
        id=str(uuid.uuid4()),
        plugin="csrf",
        severity=Severity.INFO,
        title="CSRF Token Detected",
        description="CSRF token detected in form or page.",
        url=target_url,
        parameter=None,
        method="GET",
        payload=None,
        evidence="CSRF token keyword found in response HTML.",
        request=HTTPRequest(
            method="GET",
            url=target_url,
            headers=dict(resp.request.headers),
            body=None,
            cookies=dict(resp.request._cookies) if hasattr(resp.request, "_cookies") else {},
        ),
        response=None,
        remediation=None,
        references=[
            "https://owasp.org/www-community/attacks/csrf"
        ],
        cwe_id=None,
        cvss_score=None,
        cvss_vector=None,
        confidence=Confidence.TENTATIVE,
    )


def scan_res_headers(headers: dict) -> Finding:
    """
    HTTP 응답 헤더에서 CSRF 관련 보안 헤더를 검사합니다.
    CSRF 보호 헤더가 없으면 Finding 객체를 반환합니다.
    """
    headings_to_check = ["X-Frame-Options", "Content-Security-Policy", "SameSite"]
    # TODO: SameSite 쿠키 설정은 쿠키 단위로 검사해야함.
    # TODO: 와일드카드 값 * 사용 여부 검사
    # TODO: Set-Cookie, CSP 헤더 값 검사

    missing_headings = [h for h in headings_to_check if h not in headers]
    if missing_headings:
        return Finding(
            id=str(uuid.uuid4()),
            plugin="csrf",
            severity=Severity.MEDIUM,
            title="Missing CSRF Protection Headers",
            description=f"The following CSRF protection headers are missing: {', '.join(missing_headings)}.",
            url="N/A",
            parameter=None,
            method=None,
            payload=None,
            evidence=f"Missing headers: {', '.join(missing_headings)}",
            request=None,
            response=None,
            remediation="Implement appropriate CSRF protection headers such as X-Frame-Options, Content-Security-Policy, and SameSite cookies.",
            references=[
                "https://owasp.org/www-community/controls/Clickjacking_Defense_Cheat_Sheet",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
            ],
            cwe_id="CWE-352",
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            confidence=Confidence.FIRM,
        )

    return Finding(
        id=str(uuid.uuid4()),
        plugin="csrf",
        severity=Severity.INFO,
        title="All CSRF Protection Headers Present",
        description="All recommended CSRF protection headers are present in the response.",
        url="N/A",
        parameter=None,
        method=None,
        payload=None,
        evidence="All CSRF protection headers found.",
        request=None,
        response=None,
        remediation=None,
        references=[
            "https://owasp.org/www-community/controls/Clickjacking_Defense_Cheat_Sheet",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
        ],
        cwe_id=None,
        cvss_score=None,
        cvss_vector=None,
        confidence=Confidence.TENTATIVE,
    )


def scan_form_tags(html: str, resp: Any, target_url: str, ) -> Finding:
    """
    주어진 HTML에서 Form 태그 내 CSRF 취약점을 검사합니다.
    CSRF 토큰이 발견되지 않으면 Finding 객체를 반환합니다.
    """

    try:
        parser = FormParser()
        parser.feed(html or "")
        forms = parser.forms
    except Exception:
        forms = []

    if not forms:
        return Finding(
            id=str(uuid.uuid4()),
            plugin="csrf",
            severity=Severity.INFO,
            title="No Form Tags Found",
            description="No <form> tags were found on the page — no form-level CSRF checks to perform.",
            url=target_url,
            parameter=None,
            method="GET",
            payload=None,
            evidence="No <form> tags present in response HTML.",
            request=HTTPRequest(
                method="GET",
                url=target_url,
                headers=dict(resp.request.headers) if hasattr(resp, "request") and hasattr(resp.request,
                                                                                           "headers") else {},
                body=None,
                cookies=dict(resp.request._cookies) if hasattr(resp.request, "_cookies") else {},
            ),
            response=None,
            remediation="If the application uses forms, ensure anti-CSRF tokens are added to state-changing forms.",
            references=["https://owasp.org/www-community/attacks/csrf"],
            cwe_id=None,
            cvss_score=None,
            cvss_vector=None,
            confidence=Confidence.TENTATIVE,
        )

    vulnerable = []
    for idx, form in enumerate(forms):
        inputs = form.get("inputs", [])
        form_html = (form.get("html") or "").lower()

        token_found = False
        # 검증 로직: hidden input 태그 및 name/id 속성 검사, CSRF_TOKEN_KEYWORDS 포함 여부 검사
        for inp in inputs:
            name = inp.get("name", "").lower()
            idv = inp.get("id", "").lower()
            itype = inp.get("type", "").lower()

            if itype == "hidden" and ("csrf" in name or "token" in name or "authenticity" in name):
                token_found = True
                break

            if any(k.lower() in name for k in CSRF_TOKEN_KEYWORDS) or any(
                    k.lower() in idv for k in CSRF_TOKEN_KEYWORDS):
                token_found = True
                break

        if not token_found and any(k.lower() in form_html for k in CSRF_TOKEN_KEYWORDS):
            token_found = True

        if not token_found:
            vulnerable.append({"index": idx, "form": form})

    if vulnerable:
        sample = vulnerable[0]["form"]["html"] if isinstance(vulnerable[0]["form"], dict) else str(
            vulnerable[0]["form"])
        snippet = (sample[:400] + "...") if sample and len(sample) > 400 else sample
        evidence = f"{len(vulnerable)} form(s) missing CSRF token. Example snippet: {snippet}"

        return Finding(
            id=str(uuid.uuid4()),
            plugin="csrf",
            severity=Severity.HIGH,
            title="Form(s) Missing CSRF Token",
            description=("One or more <form> elements do not appear to include anti-CSRF tokens in hidden inputs "
                         "or identifiable token fields. This may allow CSRF attacks against state-changing endpoints."),
            url=target_url,
            parameter=None,
            method="GET",
            payload=None,
            evidence=evidence,
            request=HTTPRequest(
                method="GET",
                url=target_url,
                headers=dict(resp.request.headers) if hasattr(resp, "request") and hasattr(resp.request,
                                                                                           "headers") else {},
                body=None,
                cookies=dict(resp.request._cookies) if hasattr(resp.request, "_cookies") else {},
            ),
            response=None,
            remediation=("Add server-validated anti-CSRF tokens (e.g. synchronizer token pattern or SameSite cookies) "
                         "to all state-changing forms and validate them on the server side."),
            references=[
                "https://owasp.org/www-community/attacks/csrf",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            ],
            cwe_id="CWE-352",
            cvss_score=6.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
            confidence=Confidence.FIRM,
        )

    return Finding(
        id=str(uuid.uuid4()),
        plugin="csrf",
        severity=Severity.INFO,
        title="Forms Include CSRF Tokens",
        description="All detected <form> elements contain indications of anti-CSRF tokens.",
        url=target_url,
        parameter=None,
        method="GET",
        payload=None,
        evidence="CSRF token-like inputs found in all forms.",
        request=HTTPRequest(
            method="GET",
            url=target_url,
            headers=dict(resp.request.headers) if hasattr(resp, "request") and hasattr(resp.request, "headers") else {},
            body=None,
            cookies=dict(resp.request._cookies) if hasattr(resp.request, "_cookies") else {},
        ),
        response=None,
        remediation=None,
        references=["https://owasp.org/www-community/attacks/csrf"],
        cwe_id=None,
        cvss_score=None,
        cvss_vector=None,
        confidence=Confidence.TENTATIVE,
    )
