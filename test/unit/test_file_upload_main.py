"""File Upload Plugin Tests - pytest style"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
import time

from s2n.s2nscanner.interfaces import (
    PluginContext,
    PluginStatus,
    Severity,
    ScanContext,
    ScanConfig,
    PluginConfig,
)

from s2n.s2nscanner.plugins.file_upload.file_upload_main import FileUploadPlugin


@pytest.fixture
def mock_http_client():
    """Create a mock HTTP client for testing"""
    return MagicMock()


@pytest.fixture
def plugin_context(mock_http_client):
    """Create a plugin context for testing"""
    from s2n.s2nscanner.interfaces import ScannerConfig

    # Create ScannerConfig with crawl_depth
    scanner_config = ScannerConfig(crawl_depth=2)

    # Create ScanConfig with scanner_config
    scan_config = ScanConfig(
        target_url="http://test.com", scanner_config=scanner_config
    )

    scan_context = ScanContext(
        scan_id=f"test-{int(time.time())}",
        start_time=datetime.now(timezone.utc),
        config=scan_config,
        http_client=mock_http_client,
        crawler=None,
    )

    return PluginContext(
        plugin_name="file_upload",
        scan_context=scan_context,
        plugin_config=PluginConfig(
            enabled=True, timeout=5, max_payloads=10, custom_params={}
        ),
        target_urls=["http://test.com"],
        logger=None,
    )


@pytest.fixture
def plugin():
    """Create a FileUploadPlugin instance"""
    return FileUploadPlugin()


def _mock_response(text, status_code=200, headers=None):
    """Helper function to create a mock response object"""
    response = MagicMock()
    response.text = text
    response.status_code = status_code
    response.headers = headers or {}
    response.iter_lines.return_value = text.splitlines()
    response.url = "http://test.com/upload"
    return response


@pytest.mark.unit
def test_run_finds_vulnerability_on_first_page(
    plugin, plugin_context, mock_http_client
):
    """Test finding vulnerability on the initial target URL"""
    upload_form_html = """
    <html><body>
        <form action="/upload" method="post" enctype="multipart/form-data">
            <input type="file" name="upload" />
            <input type="submit" value="Upload" />
        </form>
    </body></html>
    """

    # Mock responses
    mock_http_client.get.side_effect = [
        _mock_response(upload_form_html),  # Initial page fetch (line 56 in plugin)
        _mock_response(upload_form_html),  # Page fetch in crawl loop (line 69 in plugin)
    ]

    # Create a mock finding to be returned by upload_test_files
    from s2n.s2nscanner.interfaces import Finding
    mock_finding = Finding(
        id="test-finding-1",
        plugin="file_upload",
        severity=Severity.HIGH,
        title="File Upload Vulnerability Detected",
        description="Test vulnerability",
        url="http://test.com/uploads/test.php",
        evidence="Test marker found",
        timestamp=datetime.now(timezone.utc),
        remediation="Fix it",
    )

    # Execute
    with (
        patch(
            "s2n.s2nscanner.plugins.file_upload.file_upload_main.authenticate_if_needed",
            side_effect=lambda ctx, resp, client, stats: resp,  # Just return the response as-is
        ),
        patch(
            "s2n.s2nscanner.plugins.file_upload.file_upload_main.crawl_recursive",
            return_value=["http://test.com"],
        ),
        patch(
            "s2n.s2nscanner.plugins.file_upload.file_upload_main.upload_test_files",
            return_value=[mock_finding],
        ),
    ):
        result = plugin.run(plugin_context)

    # Assert
    assert result.status == PluginStatus.SUCCESS
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == Severity.HIGH
    assert "File Upload Vulnerability Detected" in finding.title
    assert mock_http_client.get.call_count == 2


@pytest.mark.unit
def test_run_no_form_found(plugin, plugin_context, mock_http_client):
    """Test when no upload form is found after full DFS scan"""
    no_form_html = (
        "<html><body><p>그냥 텍스트입니다.</p><a href='/page2'></a></body></html>"
    )
    page2_html = "<html><body><p>여전히 아무것도 없습니다.</p></body></html>"

    mock_http_client.get.side_effect = [
        _mock_response(no_form_html),
        _mock_response(page2_html),
    ]

    # Execute
    result = plugin.run(plugin_context)

    # Assert
    assert result.status == PluginStatus.SUCCESS
    assert len(result.findings) == 0
    # The plugin scans at least the initial URL
    assert result.urls_scanned >= 1


@pytest.mark.unit
def test_run_skips_login_page(plugin, plugin_context, mock_http_client):
    """Test that the plugin skips pages that appear to be login pages"""
    login_page_html = """
    <html><body>
        <form action="/login" method="post">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="submit" value="Login" />
        </form>
    </body></html>
    """
    mock_http_client.get.return_value = _mock_response(login_page_html)

    # Execute
    result = plugin.run(plugin_context)

    # Assert
    assert result.status == PluginStatus.SUCCESS
    assert len(result.findings) == 0


@pytest.mark.unit
def test_run_handles_http_error(plugin, plugin_context, mock_http_client):
    """Test that the plugin gracefully fails when HTTP error occurs"""
    from s2n.s2nscanner.interfaces import PluginError

    mock_http_client.get.side_effect = Exception("연결 시간 초과")

    # Execute
    result = plugin.run(plugin_context)

    # Assert - plugin returns PluginError, not PluginResult with FAILED status
    assert isinstance(result, PluginError)
    assert result.error_type == "Exception"
    assert result.message == "연결 시간 초과"


@pytest.mark.unit
def test_run_with_csrf_token(plugin, plugin_context, mock_http_client):
    """Test finding vulnerability in a form with CSRF token"""
    csrf_token = "abcde12345"
    upload_form_html = f"""
    <html><body>
        <form action="/upload_with_csrf" method="post" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="{csrf_token}" />
            <input type="file" name="upload" />
            <input type="submit" value="Upload" />
        </form>
    </body></html>
    """

    # Mock responses
    mock_http_client.get.side_effect = [
        _mock_response(upload_form_html),  # Initial page fetch (line 56 in plugin)
        _mock_response(upload_form_html),  # Page fetch in crawl loop (line 69 in plugin)
    ]

    # Create a mock finding
    from s2n.s2nscanner.interfaces import Finding
    mock_finding = Finding(
        id="test-finding-2",
        plugin="file_upload",
        severity=Severity.HIGH,
        title="File Upload Vulnerability Detected",
        description="Test vulnerability with CSRF",
        url="http://test.com/uploads/test.php",
        evidence="Test marker found",
        timestamp=datetime.now(timezone.utc),
        remediation="Fix it",
    )

    # Track the call to upload_test_files to verify CSRF token was passed
    upload_test_files_mock = MagicMock(return_value=[mock_finding])

    # Execute
    with (
        patch(
            "s2n.s2nscanner.plugins.file_upload.file_upload_main.authenticate_if_needed",
            side_effect=lambda ctx, resp, client, stats: resp,  # Just return the response as-is
        ),
        patch(
            "s2n.s2nscanner.plugins.file_upload.file_upload_main.crawl_recursive",
            return_value=["http://test.com"],
        ),
        patch(
            "s2n.s2nscanner.plugins.file_upload.file_upload_main.upload_test_files",
            upload_test_files_mock,
        ),
    ):
        result = plugin.run(plugin_context)

    # Assert
    assert result.status == PluginStatus.SUCCESS
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.HIGH

    # Verify that upload_test_files was called with the correct data including CSRF token
    assert upload_test_files_mock.called
    call_args = upload_test_files_mock.call_args
    data_param = call_args[0][2]  # Third positional argument is 'data'
    assert "csrf_token" in data_param
    assert data_param["csrf_token"] == csrf_token
