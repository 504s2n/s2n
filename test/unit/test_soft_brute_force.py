import pytest
from unittest.mock import MagicMock
from types import SimpleNamespace
from s2n.s2nscanner.plugins.soft_brute_force.soft_brute_force_main import SoftBruteForcePlugin
from s2n.s2nscanner.interfaces import PluginStatus

class MockResponse:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code

@pytest.fixture
def mock_context():
    client = MagicMock()
    scan_context = SimpleNamespace(
        config=SimpleNamespace(target_url="http://example.com/login"),
        http_client=client,
        target_url="http://example.com/login"
    )
    return SimpleNamespace(scan_context=scan_context, plugin_name="soft_brute_force")

def test_rate_limiting_detected_429(mock_context):
    plugin = SoftBruteForcePlugin()
    
    mock_context.scan_context.http_client.get.return_value = MockResponse("Login Page")
    mock_context.scan_context.http_client.post.return_value = MockResponse("Too Many", 429)
    
    result = plugin.run(mock_context)
    
    assert result.status == PluginStatus.SUCCESS
    assert len(result.findings) == 0

def test_rate_limiting_not_detected(mock_context):
    plugin = SoftBruteForcePlugin()
    
    mock_context.scan_context.http_client.get.return_value = MockResponse("Login Page")
    mock_context.scan_context.http_client.post.return_value = MockResponse("Login Failed", 200)
    
    result = plugin.run(mock_context)
    
    assert result.status == PluginStatus.SUCCESS
    assert len(result.findings) == 1
    assert result.findings[0].title == "No Rate Limiting Detected"