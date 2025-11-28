from __future__ import annotations

from types import SimpleNamespace

import pytest

from s2n.s2nscanner.plugins.oscommand.oscommand_main import OSCommandPlugin, COMMON_PARAMS
from s2n.s2nscanner.plugins.oscommand.oscommand_utils import (
    build_attack_url,
    extract_params,
    match_pattern,
)


class FakeResponse:
    """HttpClient 응답을 흉내 내기 위한 단순한 테스트 더블입니다."""
    def __init__(self, text: str):
        self.text = text


class FakeHttpClient:
    """요청 URL을 기록하고 준비된 응답을 돌려주는 테스트 전용 클라이언트입니다."""
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        if "page.php" in url and "?" not in url:
            return FakeResponse('<form><input name="cmd"></form>')
        if "%3Bid" in url:
            return FakeResponse("uid=0(root)")
        return FakeResponse("safe response")


@pytest.fixture()
def fake_scan_context(monkeypatch):
    """크롤러/HTTP 클라이언트를 목으로 대체한 ScanContext를 생성합니다."""
    client = FakeHttpClient()

    def fake_crawl(base_url, client_param, depth, timeout):
        return [f"{base_url.rstrip('/')}/page.php"]

    monkeypatch.setattr(
        "s2n.s2nscanner.plugins.oscommand.oscommand_main.crawl_recursive",
        fake_crawl,
    )

    scan_context = SimpleNamespace(
        config=SimpleNamespace(target_url="http://target/app"),
        http_client=client,
        auth_adapter=None,
    )
    return scan_context


def test_oscommand_plugin_detects_vulnerability(fake_scan_context):
    """취약한 파라미터를 발견하면 SUCCESS 상태와 Finding을 반환하는지 검증합니다."""
    plugin = OSCommandPlugin()
    plugin_context = SimpleNamespace(scan_context=fake_scan_context, plugin_config=None)

    result = plugin.run(plugin_context)

    assert result.status.name == "SUCCESS"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.plugin == plugin.name
    assert finding.severity.name == "HIGH"
    assert finding.parameter == "cmd"


def test_oscommand_plugin_handles_missing_target_url():
    """target_url 정보가 없을 때 FAILED 상태와 에러 객체가 생성되는지 확인합니다."""
    plugin = OSCommandPlugin()
    scan_context = SimpleNamespace(config=None, http_client=FakeHttpClient(), auth_adapter=None)
    plugin_context = SimpleNamespace(scan_context=scan_context, plugin_config=None)

    result = plugin.run(plugin_context)

    assert result.status.name == "FAILED"
    assert not result.findings
    assert result.error is not None


def test_extract_params_returns_expected_names():
    """extract_params 함수가 HTML 입력 필드 이름을 모두 추출하는지 검증합니다."""
    html = '<input name="cmd"><input name="token">'
    params = extract_params(html, "http://example.com/page.php", COMMON_PARAMS)
    assert "cmd" in params
    assert "token" in params


def test_build_attack_url_injects_payload():
    """build_attack_url이 파라미터에 페이로드를 주입해 인코딩하는지 확인합니다."""
    url = build_attack_url("http://host/page.php", "cmd", ";id")
    assert "cmd=test%3Bid" in url


def test_match_pattern_returns_first_match():
    """match_pattern이 첫 번째 일치 정규식을 반환하는지 검증합니다."""
    matched = match_pattern("uid=0(root)", [r"foo", r"uid=\d+"])
    assert matched == r"uid=\d+"
