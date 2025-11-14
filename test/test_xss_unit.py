# test_xss_unit.py
import pytest
from s2n.s2nscanner.plugins.xss.xss import _load_payload_path


@pytest.mark.unit
def test_load_payload_path_success():
    """payload 파일이 존재하는 경우 (실제 파일 테스트)"""
    # 실제 xss_payloads.json이 있다고 가정하고 테스트
    # (프로젝트에 실제 파일이 있으므로)
    result = _load_payload_path()
    assert result.exists()
    assert result.name == "xss_payloads.json"


@pytest.mark.unit
def test_load_payload_path_not_found(tmp_path, monkeypatch):
    """payload 파일이 없는 경우 FileNotFoundError"""
    from pathlib import Path

    # xss.py 모듈의 __file__ 속성을 임시 디렉토리로 변경
    import s2n.s2nscanner.plugins.xss.xss as xss_module
    fake_file = tmp_path / "xss.py"
    fake_file.touch()  # 빈 파일 생성

    monkeypatch.setattr(xss_module, "__file__", str(fake_file))

    with pytest.raises(FileNotFoundError, match="Payload file not found"):
        _load_payload_path()


@pytest.mark.unit
def test_payload_result_dataclass():
    """PayloadResult 기본 생성 및 필드 검증"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import PayloadResult

    pr = PayloadResult(
        payload="<script>alert(1)</script>",
        context="html",
        category="reflected",
        category_ko="반사형",
        description="Test"
    )

    assert pr.payload == "<script>alert(1)</script>"
    assert pr.context == "html"
    assert pr.category == "reflected"


@pytest.mark.unit
def test_finding_as_dict():
    """Finding.as_dict() 직렬화 검증"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import Finding, PayloadResult

    pr = PayloadResult(
        payload="<img>",
        context="attribute",
        category="reflected",
        category_ko="반사형",
        description="In attribute context"
    )

    finding = Finding(
        url="https://test.com/app",
        parameter="q",
        method="GET",
        matches=[pr]
    )

    data = finding.as_dict()
    assert data["url"] == "https://test.com/app"
    assert data["parameter"] == "q"
    assert data["method"] == "GET"
    assert len(data["successful_payloads"]) == 1
    assert data["successful_payloads"][0]["payload"] == "<img>"


@pytest.mark.unit
def test_finding_multiple_matches():
    """Finding에 여러 PayloadResult 추가"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import Finding, PayloadResult

    finding = Finding(url="/test", parameter="id", method="POST")
    finding.matches.append(PayloadResult("p1", "html", "reflected", "반사형", ""))
    finding.matches.append(PayloadResult("p2", "attribute", "reflected", "반사형", ""))

    assert len(finding.matches) == 2
    data = finding.as_dict()
    assert len(data["successful_payloads"]) == 2


@pytest.mark.unit
def test_form_parser_basic_form():
    """기본 form 파싱"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import FormParser

    html = '<form action="/submit" method="POST"><input name="text" value="test"></form>'
    parser = FormParser()
    parser.feed(html)

    assert len(parser.forms) == 1
    form = parser.forms[0]
    assert form["action"] == "/submit"
    assert form["method"] == "POST"
    assert len(form["inputs"]) == 1


@pytest.mark.unit
def test_form_parser_csrf_field():
    """CSRF 토큰 필드 포함 form"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import FormParser
    from test_xss_fixtures import FORM_WITH_CSRF_HTML

    parser = FormParser()
    parser.feed(FORM_WITH_CSRF_HTML)

    form = parser.forms[0]
    assert form["method"] == "POST"
    assert any(inp["name"] == "csrf_token" for inp in form["inputs"])
    csrf_input = next(inp for inp in form["inputs"] if inp["name"] == "csrf_token")
    assert csrf_input["value"] == "abc123"
    assert csrf_input["type"] == "hidden"


@pytest.mark.unit
def test_form_parser_ignores_nameless_inputs():
    """name 속성 없는 input은 무시"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import FormParser

    html = '''
    <form>
        <input type="text" value="ignored">
        <input name="valid" value="included">
    </form>
    '''
    parser = FormParser()
    parser.feed(html)

    form = parser.forms[0]
    assert len(form["inputs"]) == 1
    assert form["inputs"][0]["name"] == "valid"


@pytest.mark.unit
def test_form_parser_multiple_forms():
    """여러 form 동시 파싱"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import FormParser

    html = '''
    <form action="/login"><input name="user"></form>
    <form action="/search"><input name="q"></form>
    '''
    parser = FormParser()
    parser.feed(html)

    assert len(parser.forms) == 2
    assert parser.forms[0]["action"] == "/login"
    assert parser.forms[1]["action"] == "/search"


@pytest.mark.unit
def test_form_parser_default_method():
    """method 속성 없으면 GET 기본값"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import FormParser

    html = '<form><input name="q"></form>'
    parser = FormParser()
    parser.feed(html)

    assert parser.forms[0]["method"] == "GET"


@pytest.mark.unit
def test_form_parser_textarea_select():
    """textarea, select 요소도 파싱"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import FormParser

    html = '''
    <form>
        <textarea name="comment"></textarea>
        <select name="category"></select>
    </form>
    '''
    parser = FormParser()
    parser.feed(html)

    inputs = parser.forms[0]["inputs"]
    assert len(inputs) == 2
    assert any(inp["name"] == "comment" for inp in inputs)
    assert any(inp["name"] == "category" for inp in inputs)


@pytest.mark.unit
def test_input_point_detector_from_query(responses_mock, mock_http_client):
    """URL 쿼리 파라미터 탐지"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import InputPointDetector

    responses_mock.get("https://app.test/search", body="<html></html>")

    detector = InputPointDetector(mock_http_client)
    points = detector.detect("https://app.test/search?q=test&lang=ko")

    assert len(points) >= 1
    url_point = next((p for p in points if p.source == "url"), None)
    assert url_point is not None
    assert url_point.parameters["q"] == "test"
    assert url_point.parameters["lang"] == "ko"
    assert url_point.method == "GET"


@pytest.mark.unit
def test_input_point_detector_from_form(responses_mock, mock_http_client):
    """HTML form 입력 지점 탐지"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import InputPointDetector
    from test_xss_fixtures import FORM_WITH_CSRF_HTML

    responses_mock.get("https://app.test/form", body=FORM_WITH_CSRF_HTML, status=200)

    detector = InputPointDetector(mock_http_client)
    points = detector.detect("https://app.test/form")

    form_point = next((p for p in points if p.source == "form"), None)
    assert form_point is not None
    assert form_point.method == "POST"
    assert "csrf_token" in form_point.parameters
    assert form_point.parameters["csrf_token"] == "abc123"
    assert "comment" in form_point.parameters


@pytest.mark.unit
def test_input_point_detector_hidden_field_preserved(responses_mock, mock_http_client):
    """hidden 필드도 parameters에 포함"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import InputPointDetector

    html = '''
    <form method="POST">
        <input type="hidden" name="token" value="secret123">
        <input type="text" name="query">
    </form>
    '''
    responses_mock.get("https://test.com/", body=html, status=200)

    detector = InputPointDetector(mock_http_client)
    points = detector.detect("https://test.com/")

    form_point = points[0]
    assert form_point.parameters["token"] == "secret123"
    assert form_point.parameters["query"] == "test"  # 기본값


@pytest.mark.unit
def test_input_point_detector_http_error(responses_mock, mock_http_client, caplog):
    """HTTP 오류 시 graceful 처리"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import InputPointDetector

    responses_mock.get("https://test.com/error", status=500)

    detector = InputPointDetector(mock_http_client)
    points = detector.detect("https://test.com/error?q=1")

    # URL 파라미터는 탐지되지만 form은 실패
    assert len(points) >= 1
    assert "Failed to detect input points" in caplog.text or len(points) == 1


@pytest.mark.unit
def test_input_point_detector_submit_button_handling(responses_mock, mock_http_client):
    """submit/button 타입 필드 처리"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import InputPointDetector

    html = '''
    <form>
        <input type="text" name="username">
        <input type="submit" name="btnSubmit" value="Login">
        <input type="button" name="btnCancel" value="Cancel">
    </form>
    '''
    responses_mock.get("https://test.com/", body=html, status=200)

    detector = InputPointDetector(mock_http_client)
    points = detector.detect("https://test.com/")

    form_point = points[0]
    # submit/button은 value 또는 name을 기본값으로 사용
    assert form_point.parameters["btnSubmit"] == "Login"
    assert form_point.parameters["btnCancel"] == "Cancel"


@pytest.mark.unit
def test_input_point_detector_action_url_join(responses_mock, mock_http_client):
    """form action의 상대 경로 처리"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import InputPointDetector

    html = '<form action="/submit"><input name="data"></form>'
    responses_mock.get("https://test.com/page", body=html, status=200)

    detector = InputPointDetector(mock_http_client)
    points = detector.detect("https://test.com/page")

    form_point = points[0]
    assert form_point.url == "https://test.com/submit"


@pytest.mark.unit
def test_detect_context_html():
    """HTML 컨텍스트 탐지"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import ReflectedScanner

    body = "<body><script>alert(1)</script></body>"
    payload = "<script>alert(1)</script>"

    assert ReflectedScanner._detect_context(body, payload) == "html"


@pytest.mark.unit
def test_detect_context_attribute():
    """속성 컨텍스트 탐지"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import ReflectedScanner

    payload = "test_payload"
    body = f'<input value="{payload}">'

    assert ReflectedScanner._detect_context(body, payload) == "attribute"


@pytest.mark.unit
def test_detect_context_mixed():
    """혼합 컨텍스트 (원본 + 이스케이프)"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import ReflectedScanner

    payload = "<payload>"
    body = '<div data="<payload>">&lt;payload&gt;</div>'

    # 실제 _detect_context는 attribute를 반환 (첫 번째 발견된 컨텍스트)
    assert ReflectedScanner._detect_context(body, payload) == "attribute"


@pytest.mark.unit
def test_record_creates_finding(payload_path, mock_http_client):
    """_record가 Finding을 생성하고 matches 추가"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import (
        ReflectedScanner, InputPoint, PayloadResult
    )

    scanner = ReflectedScanner(payload_path, http_client=mock_http_client)

    point = InputPoint(
        url="https://test.com/app",
        method="GET",
        parameters={"q": "test"},
        source="url"
    )

    result = PayloadResult(
        payload="<script>",
        context="html",
        category="reflected",
        category_ko="반사형",
        description="Test"
    )

    scanner._record(point, "q", result)

    key = "https://test.com/app|q|GET"
    assert key in scanner.findings
    assert len(scanner.findings[key].matches) == 1
    assert scanner.findings[key].parameter == "q"


@pytest.mark.unit
def test_record_appends_to_existing_finding(payload_path, mock_http_client):
    """동일 입력 지점에 여러 페이로드 결과 추가"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import (
        ReflectedScanner, InputPoint, PayloadResult
    )

    scanner = ReflectedScanner(payload_path, http_client=mock_http_client)

    point = InputPoint(url="/test", method="POST", parameters={}, source="form")

    scanner._record(point, "param1", PayloadResult("p1", "html", "reflected", "반사형", ""))
    scanner._record(point, "param1", PayloadResult("p2", "attribute", "reflected", "반사형", ""))

    key = "/test|param1|POST"
    assert len(scanner.findings[key].matches) == 2


@pytest.mark.unit
def test_record_stored_uses_special_key(payload_path, mock_http_client):
    """_record_stored는 parameter=[stored] 사용"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import (
        ReflectedScanner, InputPoint, PayloadResult
    )

    scanner = ReflectedScanner(payload_path, http_client=mock_http_client)

    point = InputPoint(url="/feed", method="POST", parameters={}, source="form")
    result = PayloadResult("stored_p", "stored", "stored", "저장형", "Persisted")

    scanner._record_stored(point, result)

    key = "/feed|[stored]|POST"
    assert key in scanner.findings
    assert scanner.findings[key].parameter == "[stored]"


@pytest.mark.unit
def test_as_s2n_findings_conversion(payload_path, mock_http_client):
    """_as_s2n_findings가 S2NFinding 리스트 반환"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import (
        ReflectedScanner, InputPoint, PayloadResult
    )

    scanner = ReflectedScanner(payload_path, http_client=mock_http_client)

    point = InputPoint(url="/app", method="GET", parameters={"id": "1"}, source="url")
    scanner._record(point, "id", PayloadResult("<img>", "html", "reflected", "반사형", "Test"))

    findings = scanner._as_s2n_findings()

    assert len(findings) == 1
    finding = findings[0]
    assert finding.plugin == "xss"
    assert finding.url == "/app"
    assert finding.parameter == "id"
    assert finding.payload == "<img>"
    # Severity는 HIGH, Confidence는 FIRM (fallback 포함)
    assert hasattr(finding, "severity")
    assert hasattr(finding, "confidence")
