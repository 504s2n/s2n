from typing import Optional
from types import SimpleNamespace
import pytest
import pkgutil
import importlib
from datetime import datetime

from test.mock_helper import to_mock_interface

from s2n.s2nscanner import plugins as plugins_pkg
from s2n.s2nscanner.interfaces import (
    AuthType, ScanConfig, ScanContext, ScannerConfig, PluginConfig, AuthConfig,
    NetworkConfig, OutputConfig, LoggingConfig, ScanRequest, CLIArguments,
    PluginContext, HTTPRequest, HTTPResponse, Finding, PluginError, PluginResult,
    ScanSummary, ScanMetadata, ScanReport, ErrorReport, ProgressInfo,
    ConsoleOutput, JSONOutput, Severity,  ConsoleMode, 
    PluginStatus
)


"""============ HTTP Mock Classes ============"""
# Lightweight HTTP/session/request mocks used across tests
class MockRequest:
    def get(self, **kwargs):
        return MockResponse(**kwargs)

    def __init__(self):
        self.headers = {"Host": "example.com"}
        self._cookies = {}
        self.request = self.get


class MockResponse:
    def __init__(self, text="", headers=None, **kwargs):
        self.text = text
        self.headers = headers or {}
        self.request = MockRequest()
        self.kwargs = kwargs

    def get(self, **kwargs):
        return self

class MockHTTPClient:

    def __init__(self, text="", **kwargs):
        self.s = MockSession(text)
        self.headers = {}
        self.calls = []
    
    def request(self, **kwargs):
        self.calls.append(kwargs)
        return MockRequest(**kwargs)
    
    def response(self, **kwargs):
        self.calls.append(kwargs)
        return MockResponse(**kwargs)
    
    def get(self, url, **kwargs):
        self.calls.append(url)
        if "page.php" in url and "?" not in url:
            return MockResponse('<form><input name="cmd"></form>')
        if "%3Bid" in url:
            return MockResponse("uid=0(root)")
        return MockResponse("safe response")

    

    

class MockSession:
    def __init__(self, text):
        self._text = text
        self.headers = {}

    def get(self, _url, timeout=10):
        # keep references to avoid unused-argument lint complaints
        _ = _url
        _ = timeout
        return MockResponse(self._text, headers={})

def gen_http_client(text="<html></html>"):
    return SimpleNamespace(s=MockSession(text))




def _is_fatal_exception(exc):
    return isinstance(exc, (SystemExit, KeyboardInterrupt))


"""============ Mock Scan Interfaces ============"""

class MockScannerConfig:
    def __init__(self, obj: Optional[ScannerConfig] = None):
        param = obj or ScannerConfig()
        self.__dict__.update(to_mock_interface(param, class_type=ScannerConfig).__dict__)
        

class MockScanConfig:
    def __init__(self, obj: Optional[ScanConfig] = None,
                 target_url: Optional[str] = None,
                 ):
        self.target_url = target_url or "http://127.0.0.1"
        param = obj or ScanConfig(target_url=self.target_url)
        self.__dict__.update(to_mock_interface(param, class_type=ScanConfig).__dict__)


class MockScanContext:
    def __init__(self, obj: Optional[ScanContext] = None):
        param = obj or ScanContext(
            scan_id=f"test-scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            start_time=datetime.utcnow(),
            config=to_mock_interface(obj, class_type=ScanConfig),
            http_client=gen_http_client(),
            crawler=None
        )
        self.__dict__.update(to_mock_interface(param, class_type=ScanContext).__dict__)
    pass


class MockPluginConfig:
    def __init__(self, obj: Optional[PluginConfig] = None):
        param = obj or PluginConfig()
        self.__dict__.update(to_mock_interface(param, class_type=PluginConfig).__dict__)


class MockAuthConfig:
    def __init__(self, obj: Optional[AuthConfig] = None):
        param = obj or AuthConfig(auth_type=AuthType.NONE)
        self.__dict__.update(to_mock_interface(param, class_type=AuthConfig).__dict__)


class MockNetworkConfig:
    def __init__(self, obj: Optional[NetworkConfig] = None):
        param = obj or NetworkConfig()
        self.__dict__.update(to_mock_interface(param, class_type=NetworkConfig).__dict__)


class MockOutputConfig:
    def __init__(self, obj: Optional[OutputConfig] = None):
        param = obj or OutputConfig()
        self.__dict__.update(to_mock_interface(param, class_type=OutputConfig).__dict__)


class MockLoggingConfig:
    def __init__(self, obj: Optional[LoggingConfig] = None):
        param = obj or LoggingConfig()
        self.__dict__.update(to_mock_interface(param, class_type=LoggingConfig).__dict__)




class MockScanRequest:
    def __init__(self, obj: Optional[ScanRequest] = None):
        param = obj or ScanRequest(target_url="http://example.com")
        self.__dict__.update(to_mock_interface(param, class_type=ScanRequest).__dict__)


class MockCLIArguments:
    def __init__(self, obj: Optional[CLIArguments] = None):
        param = obj or CLIArguments(url="http://example.com")
        self.__dict__.update(to_mock_interface(param, class_type=CLIArguments).__dict__)


class MockPluginContext:
    def __init__(self, obj: Optional[PluginContext] = None):
        # 딕셔너리로 전달된 경우 처리
        if isinstance(obj, dict):
            target_url = obj.get("target_urls", ["http://example.com"])[0] if obj.get("target_urls") else "http://example.com"
            http_client = obj.get("http_client", gen_http_client())
            target_urls = obj.get("target_urls", ["http://example.com"])
            
            mock_scan_config = ScanConfig(target_url=target_url)
            mock_scan_context = ScanContext(
                scan_id="test-scan-1",
                start_time=datetime.utcnow(),
                config=mock_scan_config,
                http_client=http_client,
                crawler=None
            )
            mock_plugin_config = PluginConfig()
            
            param = PluginContext(
                plugin_name="test_plugin",
                scan_context=mock_scan_context,
                plugin_config=mock_plugin_config,
                target_urls=target_urls
            )
        else:
            # PluginContext 인스턴스이거나 None인 경우
            mock_scan_config = ScanConfig(target_url= getattr(obj, "target_urls")[0] if hasattr(obj , "target_urls") and len(getattr(obj, "target_urls")) >= 1 else "http://example.com")
            mock_scan_context = ScanContext(
                scan_id="test-scan-1",
                start_time=datetime.utcnow(),
                config=mock_scan_config,
                http_client=gen_http_client(),
                crawler=None
            )
            mock_plugin_config = PluginConfig()
            
            param = obj or PluginContext(
                plugin_name="test_plugin",
                scan_context=mock_scan_context,
                plugin_config=mock_plugin_config
            )
        self.__dict__.update(to_mock_interface(param, class_type=PluginContext).__dict__)


class MockHTTPRequest:
    def __init__(self, obj: Optional[HTTPRequest] = None):
        param = obj or HTTPRequest(method="GET", url="http://example.com")
        self.__dict__.update(to_mock_interface(param, class_type=HTTPRequest).__dict__)


class MockHTTPResponse:
    def __init__(self, obj: Optional[HTTPResponse] = None):
        param = obj or HTTPResponse(status_code=200)
        self.__dict__.update(to_mock_interface(param, class_type=HTTPResponse).__dict__)


class MockFinding:
    def __init__(self, obj: Optional[Finding] = None):
        param = obj or Finding(
            id="test-finding-1",
            plugin="test_plugin",
            severity=Severity.INFO,
            title="Test Finding",
            description="This is a test finding"
        )
        self.__dict__.update(to_mock_interface(param, class_type=Finding).__dict__)


class MockPluginError:
    def __init__(self, obj: Optional[PluginError] = None):
        param = obj or PluginError(error_type="TestError", message="Test error message")
        self.__dict__.update(to_mock_interface(param, class_type=PluginError).__dict__)


class MockPluginResult:
    def __init__(self, obj: Optional[PluginResult] = None):
        param = obj or PluginResult(plugin_name="test_plugin", status=PluginStatus.SUCCESS)
        self.__dict__.update(to_mock_interface(param, class_type=PluginResult).__dict__)


class MockScanSummary:
    def __init__(self, obj: Optional[ScanSummary] = None):
        param = obj or ScanSummary()
        self.__dict__.update(to_mock_interface(param, class_type=ScanSummary).__dict__)


class MockScanMetadata:
    def __init__(self, obj: Optional[ScanMetadata] = None):
        param = obj or ScanMetadata(
            hostname="localhost",
            username="testuser",
            python_version="3.9.0",
            os_info="Linux"
        )
        self.__dict__.update(to_mock_interface(param, class_type=ScanMetadata).__dict__)


class MockScanReport:
    def __init__(self, obj: Optional[ScanReport] = None):
        mock_scan_config = ScanConfig(target_url= getattr(obj, "target_url") if hasattr(obj , "target_url") else "http://example.com")
        param = obj or ScanReport(
            scan_id="test-scan-1",
            target_url="http://example.com",
            scanner_version="0.1.0",
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            duration_seconds=1.0,
            config=mock_scan_config
        )
        self.__dict__.update(to_mock_interface(param, class_type=ScanReport).__dict__)


class MockErrorReport:
    def __init__(self, obj: Optional[ErrorReport] = None):
        param = obj or ErrorReport(error_type="TestError", message="Test error message")
        self.__dict__.update(to_mock_interface(param, class_type=ErrorReport).__dict__)


class MockProgressInfo:
    def __init__(self, obj: Optional[ProgressInfo] = None):
        param = obj or ProgressInfo(current=1, total=10, percentage=10.0, message="Processing...")
        self.__dict__.update(to_mock_interface(param, class_type=ProgressInfo).__dict__)


class MockConsoleOutput:
    def __init__(self, obj: Optional[ConsoleOutput] = None):
        param = obj or ConsoleOutput(mode=ConsoleMode.SUMMARY)
        self.__dict__.update(to_mock_interface(param, class_type=ConsoleOutput).__dict__)


class MockJSONOutput:
    def __init__(self, obj: Optional[JSONOutput] = None):
        mock_scan_report = ScanReport(
            scan_id="test-scan-1",
            target_url=getattr(obj, "target_url") if hasattr(obj, "target_url") else "http://example.com",
            scanner_version="0.1.0",
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
            duration_seconds=1.0,
            config=ScanConfig(target_url="http://example.com")
        )
        param = obj or JSONOutput(scan_report=mock_scan_report)
        self.__dict__.update(to_mock_interface(param, class_type=JSONOutput).__dict__)





"""============ Plugin Discovery Tests ============"""

def test_plugins_package_discoverable():
    assert hasattr(plugins_pkg, "__path__"), "plugins package must be a package"
    found = {info.name for info in pkgutil.iter_modules(plugins_pkg.__path__)}
    expected = {"brute_force", "csrf", "file_upload", "oscommand", "sqlinjection", "xss"}
    assert expected.intersection(found), f"No expected plugin subpackages found in {found}"


def test_plugin_submodules_importable():
    discovered = {info.name: info for info in pkgutil.iter_modules(plugins_pkg.__path__)}
    assert discovered, "No plugin subpackages discovered"

    for plugin_name in discovered:
        full_pkg_name = f"{plugins_pkg.__name__}.{plugin_name}"
        try:
            plugin_pkg = importlib.import_module(full_pkg_name)
        except Exception as exc:
            pytest.fail(f"[]: Failed to import plugin package {full_pkg_name}: {exc}")

        pkg_path = getattr(plugin_pkg, "__path__", None)
        if not pkg_path:
            continue

        for modinfo in pkgutil.iter_modules(pkg_path):
            if modinfo.name.startswith("test_"):
                continue
            mod_fullname = f"{full_pkg_name}.{modinfo.name}"
            try:
                importlib.import_module(mod_fullname)
            except Exception as exc:
                pytest.fail(f"Failed to import module {mod_fullname}: {exc}")
