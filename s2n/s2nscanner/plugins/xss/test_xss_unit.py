# test_xss_unit.py
import pytest
from s2n.s2nscanner.plugins.xss.xss import (
    _parse_cookies, _finding_to_dict, _load_payload_path, _prompt
)


@pytest.mark.unit
def test_parse_cookies_multiple():
    """여러 쿠키 파싱 테스트"""
    result = _parse_cookies("a=1; b=two")
    assert result == {"a": "1", "b": "two"}


@pytest.mark.unit
def test_parse_cookies_empty():
    """빈 쿠키 문자열 테스트"""
    result = _parse_cookies("")
    assert result == {}


@pytest.mark.unit
def test_parse_cookies_no_equals():
    """= 기호 없는 쿠키는 무시"""
    result = _parse_cookies("invalid; a=1")
    assert result == {"a": "1"}


@pytest.mark.unit
def test_finding_to_dict_with_severity_enum():
    """Severity Enum을 문자열로 변환"""
    from types import SimpleNamespace
    from datetime import datetime, timezone

    finding = SimpleNamespace(
        id="xss-1",
        plugin="xss",
        severity=SimpleNamespace(value="HIGH"),
        title="XSS Found",
        description="Test",
        url="https://test.com",
        parameter="q",
        method="GET",
        payload="<script>",
        evidence="reflected",
        timestamp=datetime.now(timezone.utc)
    )

    result = _finding_to_dict(finding)
    assert result["severity"] == "HIGH"
    assert "T" in result["timestamp"]  # ISO format


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
def test_prompt_keyboard_interrupt(monkeypatch):
    """Ctrl+C 시 SystemExit(0)"""
    monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(KeyboardInterrupt()))

    with pytest.raises(SystemExit) as exc_info:
        _prompt("cookie> ")

    assert exc_info.value.code == 0


@pytest.mark.unit
def test_prompt_eof_error(monkeypatch):
    """Ctrl+D (EOF) 시 SystemExit(0)"""
    monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError()))

    with pytest.raises(SystemExit) as exc_info:
        _prompt("url> ")

    assert exc_info.value.code == 0


@pytest.mark.unit
def test_prompt_normal_input(monkeypatch):
    """정상 입력 처리"""
    monkeypatch.setattr("builtins.input", lambda _: "test_value")
    result = _prompt("input> ")
    assert result == "test_value"


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
