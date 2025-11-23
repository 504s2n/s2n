from requests.cookies import MockResponse
from test.mock_data import MockHTTPClient
from test.mock_data import MockRequest
from test.unit.test_csrf_data import (
    HTML_NO_FORMS,
    HTML_WITH_CSRF_TOKEN,
    HTML_WITHOUT_CSRF,
)

from s2n.s2nscanner.plugins.csrf import csrf_scan as csrf_scan_module


def test_scan_html_detects_and_missing_token():
    resp = MockHTTPClient()
    resp.request = MockRequest()
    resp.request.headers = {
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "",
        "SameSite": "Lax",
    }

    found = csrf_scan_module.scan_html(HTML_WITH_CSRF_TOKEN, resp, "http://t")
    assert "Token" in found.title
    assert found.severity.name == "INFO"

    missing = csrf_scan_module.scan_html(HTML_WITHOUT_CSRF, resp, "http://t")
    assert "Not Found" in missing.title
    assert missing.severity.name == "HIGH"


def test_scan_res_headers_checks_presence():
    # missing headers -> MEDIUM severity
    missing = csrf_scan_module.scan_res_headers({})
    assert missing.severity.name == "MEDIUM"
    assert "Missing CSRF Protection Headers" in missing.title

    ok = csrf_scan_module.scan_res_headers(
        {"X-Frame-Options": "DENY", "Content-Security-Policy": "", "SameSite": "Lax"}
    )
    assert ok.severity.name == "INFO"


def test_scan_form_tags_variants():
    resp = MockRequest()

    no_forms = csrf_scan_module.scan_form_tags(HTML_NO_FORMS, resp, "http://t")
    assert "No Form Tags Found" in no_forms.title

    missing = csrf_scan_module.scan_form_tags(HTML_WITHOUT_CSRF, resp, "http://t")
    assert missing.severity.name == "HIGH"
    assert "Form(s) Missing CSRF Token" in missing.title

    ok = csrf_scan_module.scan_form_tags(HTML_WITH_CSRF_TOKEN, resp, "http://t")
    assert ok.severity.name == "INFO"


def test_csrf_scan_integration_with_mock_session():
    http_client = MockHTTPClient()
    results = csrf_scan_module.csrf_scan(
        "http://example.local", http_client=http_client, plugin_context=None
    )  # type: ignore
    # csrf_scan returns a list of three Finding objects (html_result, http_result, html_form_result)
    assert isinstance(results, list)
    assert len(results) == 3
