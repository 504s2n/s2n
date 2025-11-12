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
    def __init__(self, text: str):
        self.text = text


class FakeHttpClient:
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
    plugin = OSCommandPlugin()
    scan_context = SimpleNamespace(config=None, http_client=FakeHttpClient(), auth_adapter=None)
    plugin_context = SimpleNamespace(scan_context=scan_context, plugin_config=None)

    result = plugin.run(plugin_context)

    assert result.status.name == "FAILED"
    assert not result.findings
    assert result.error is not None


def test_extract_params_returns_expected_names():
    html = '<input name="cmd"><input name="token">'
    params = extract_params(html, "http://example.com/page.php", COMMON_PARAMS)
    assert "cmd" in params
    assert "token" in params


def test_build_attack_url_injects_payload():
    url = build_attack_url("http://host/page.php", "cmd", ";id")
    assert "cmd=test%3Bid" in url


def test_match_pattern_returns_first_match():
    matched = match_pattern("uid=0(root)", [r"foo", r"uid=\d+"])
    assert matched == r"uid=\d+"
