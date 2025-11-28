from test.mock_data import MockHTTPClient
from test.mock_data import MockPluginContext
from s2n.s2nscanner.plugins.csrf import csrf_main
from s2n.s2nscanner.interfaces import Finding, PluginStatus, Severity, PluginResult



def test_main_run_uses_csrf_scan(monkeypatch):
    # arrange: replace csrf_scan with a stub that returns a Finding list
    fake_finding = Finding(
        id="1",
        plugin="csrf",
        severity=Severity.INFO,
        title="fake",
        description="fake",
    )

    # monkeypatch csrf_scan function in csrf_main module (not csrf_scan_module)
    monkeypatch.setattr(csrf_main, "csrf_scan", lambda url, http_client=None, plugin_context=None: [fake_finding])

    plugin_context = MockPluginContext(obj={
        "http_client": MockHTTPClient(),
        "target_urls": ["http://example.local"]
    }) 

    scanner = csrf_main.main()
    result = scanner.run(plugin_context)  # type: ignore[arg-type]

    # result should be a PluginResult dataclass
    assert isinstance(result, PluginResult)
    assert len(result.findings) == 1
    # When findings present, status should be PARTIAL
    assert result.status == PluginStatus.PARTIAL
