
import pytest
from unittest.mock import MagicMock, patch
from s2n.s2nscanner.plugins.sqlinjection.sqli_main import SQLInjectionPlugin
from s2n.s2nscanner.interfaces import PluginStatus
from types import SimpleNamespace

class MockResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code

class MockHttpClient:
    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        if "id=1' OR '1'='1' -- " in url:
            return MockResponse("ID: 1, admin") # Success indicator
        return MockResponse("safe response")

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return MockResponse("safe response")

@pytest.fixture
def mock_context():
    client = MockHttpClient()
    scan_context = SimpleNamespace(
        target_url="http://example.com/page.php?id=1",
        http_client=client,
        auth_config=SimpleNamespace(auth_adapter=None)
    )
    return SimpleNamespace(scan_context=scan_context)

def test_sqli_plugin_detects_boolean_based(mock_context):
    plugin = SQLInjectionPlugin()
    result = plugin.run(mock_context)
    print("PluginStatus: %s", result)
    
    # TODO: Partial reason
    assert result.status == PluginStatus.PARTIAL
    assert len(result.findings) > 0
    finding = result.findings[0]
    assert "SQL Injection" in finding.title
    assert "' OR '1'='1' -- " in finding.payload

def test_sqli_plugin_sends_sleep_payload(mock_context):
    # This test verifies that the sleep payload is sent
    plugin = SQLInjectionPlugin()
    
    # Mock time.time to simulate delay for time-based check
    with patch('time.time') as mock_time:
        mock_time.side_effect = [0, 0, 0, 6] # start, start_req, end_req (diff 6 > 4.5)
        
        # We need to ensure the boolean check fails so it proceeds to time-based
        mock_context.scan_context.http_client.get = MagicMock(side_effect=[
            MockResponse("safe"), # Boolean check fails
            MockResponse("safe"), # Time check response
            MockResponse("<html></html>") # Form scan page load
        ])
        
        result = plugin.run(mock_context)
        
        # Check if time payload was sent
        calls = mock_context.scan_context.http_client.get.call_args_list
        time_payload_sent = any("SLEEP(1)" in str(call) for call in calls)
        assert time_payload_sent
