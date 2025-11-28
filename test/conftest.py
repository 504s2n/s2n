"""
Pytest fixtures for integration and unit tests.
"""

import pytest
from types import SimpleNamespace
import responses

try:
    from s2n.s2nscanner.interfaces import PluginConfig
    from s2n.s2nscanner.clients.http_client import HttpClient

    HAS_INTERFACES = True
except ImportError:
    HAS_INTERFACES = False


@pytest.fixture
def responses_mock():
    """Provides a responses mock instance for mocking HTTP requests."""
    with responses.RequestsMock() as rsps:
        yield rsps


@pytest.fixture
def payload_path(tmp_path):
    """Creates a temporary JSON payload file for XSS testing."""
    import json

    payload_file = tmp_path / "xss_payloads.json"
    payloads = {
        "metadata": {"scanner": "s2n-test", "version": "1.0.0"},
        "payloads": {
            "html_context": {
                "basic": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                ]
            }
        },
    }

    payload_file.write_text(json.dumps(payloads, ensure_ascii=False))
    return payload_file


@pytest.fixture
def mock_http_client():
    """HttpClient wrapper 모킹"""
    if HAS_INTERFACES:
        return HttpClient()
    else:
        return SimpleNamespace(
            get=lambda *args, **kwargs: SimpleNamespace(text="", status_code=200),
            post=lambda *args, **kwargs: SimpleNamespace(text="", status_code=200),
        )


def create_plugin_context(target_urls=None, **kwargs):
    """
    Creates a PluginContext with the given target URLs and optional parameters.
    This function can be used directly or through the pytest fixture.

    Args:
        target_urls: List of target URLs or a single URL string
        **kwargs: Additional parameters to customize the context

    Returns:
        PluginContext instance
    """
    if isinstance(target_urls, str):
        target_urls = [target_urls]

    target_url = target_urls[0] if target_urls else "http://example.com"

    if HAS_INTERFACES:
        # Create real instances using ScanConfig directly
        from s2n.s2nscanner.interfaces import ScanConfig, ScanContext
        from datetime import datetime, timezone
        import time

        scan_config = ScanConfig(target_url=target_url)

        scan_context = ScanContext(
            scan_id=f"test-{int(time.time())}",
            start_time=datetime.now(timezone.utc),
            config=scan_config,
            http_client=HttpClient(),
            crawler=None,
        )

        plugin_config = PluginConfig(
            enabled=kwargs.get("enabled", True),
            timeout=kwargs.get("timeout", 5),
            max_payloads=kwargs.get("max_payloads", 10),
            custom_params=kwargs.get("custom_params", {}),
        )

        from s2n.s2nscanner.interfaces import PluginContext

        return PluginContext(
            plugin_name="xss",
            scan_context=scan_context,
            plugin_config=plugin_config,
            target_urls=target_urls if target_urls else [target_url],
            logger=None,
        )
    else:
        # Fallback to SimpleNamespace
        scan_config = SimpleNamespace(
            target_url=target_url,
            max_depth=kwargs.get("max_depth", 2),
            timeout=kwargs.get("timeout", 5),
        )

        scan_context = SimpleNamespace(
            config=scan_config, http_client=SimpleNamespace(), target_url=target_url
        )

        plugin_config = SimpleNamespace(
            enabled=kwargs.get("enabled", True),
            timeout=kwargs.get("timeout", 5),
            max_payloads=kwargs.get("max_payloads", 10),
            custom_params=kwargs.get("custom_params", {}),
        )

        return SimpleNamespace(scan_context=scan_context, plugin_config=plugin_config)


@pytest.fixture
def plugin_context_factory():
    """
    Factory fixture that creates PluginContext instances.
    """
    return create_plugin_context
