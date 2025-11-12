# conftest.py
import json
import pytest
from pathlib import Path
import shutil

# CRITICAL: 실제 import 경로 사용
try:
    from s2n.s2nscanner.interfaces import (
        PluginContext, ScanContext, PluginConfig,
        PluginResult, PluginStatus, Severity, Confidence,
        ScanConfig  # ← ScanConfig 추가
    )
    from s2n.s2nscanner.http.client import HttpClient
    HAS_INTERFACES = True
except ImportError:
    # SimpleNamespace fallback (테스트 대상)
    from types import SimpleNamespace
    HAS_INTERFACES = False

    class PluginContext(SimpleNamespace):
        pass

    class ScanContext(SimpleNamespace):
        pass

    class PluginConfig(SimpleNamespace):
        pass

    class PluginResult(SimpleNamespace):
        pass

    class PluginStatus:
        SUCCESS = "success"
        FAILED = "failed"
        SKIPPED = "skipped"

    class Severity:
        HIGH = "HIGH"

    class Confidence:
        FIRM = "firm"

    class ScanConfig(SimpleNamespace):  # ← ScanConfig fallback 추가
        pass

    # HttpClient fallback
    import requests

    class HttpClient:
        def __init__(self):
            self.s = requests.Session()

        def get(self, *args, **kwargs):
            return self.s.get(*args, **kwargs)

        def post(self, *args, **kwargs):
            return self.s.post(*args, **kwargs)

from .test_fixtures import SAMPLE_PAYLOADS_JSON


@pytest.fixture(scope="session")
def sample_payloads():
    """테스트용 페이로드 리스트"""
    from .test_fixtures import SAMPLE_PAYLOADS
    return SAMPLE_PAYLOADS


@pytest.fixture(scope="session")
def payload_path(tmp_path_factory):
    """실제 xss_payloads.json을 임시 경로에 복사 또는 생성"""
    real_payload = Path(__file__).parent / "xss_payloads.json"
    tmp_dir = tmp_path_factory.mktemp("xss")
    tmp_payload = tmp_dir / "xss_payloads.json"

    if real_payload.exists():
        # 실제 파일이 있으면 복사
        shutil.copy(real_payload, tmp_payload)
    else:
        # 없으면 test_fixtures의 샘플 구조로 생성
        tmp_payload.write_text(
            json.dumps(SAMPLE_PAYLOADS_JSON, ensure_ascii=False),
            encoding="utf-8"
        )

    return tmp_payload


@pytest.fixture
def mock_http_client():
    """HttpClient wrapper를 모킹한 픽스처

    IMPORTANT: ReflectedScanner는 getattr(transport, 's', None)로
    내부 Session 객체에 접근하므로 HttpClient 구조를 유지해야 함.
    """
    client = HttpClient()
    return client


@pytest.fixture
def plugin_context_factory(mock_http_client):
    """PluginContext 생성 헬퍼 팩토리"""
    from datetime import datetime, timezone
    import time

    def _factory(target_urls=None, plugin_config=None):
        if target_urls is None:
            target_urls = ["https://test.com"]

        if plugin_config is None:
            plugin_config = PluginConfig(
                enabled=True,
                timeout=5,
                max_payloads=50,
                custom_params={}
            )

        # ScanConfig는 이미 상단에서 import됨 (조건부)
        scan_config = ScanConfig(target_url=target_urls[0] if target_urls else "")

        scan_context = ScanContext(
            scan_id=f"test-{int(time.time())}",
            start_time=datetime.now(timezone.utc),
            config=scan_config,
            http_client=mock_http_client,
            crawler=None
        )

        return PluginContext(
            plugin_name="xss",
            scan_context=scan_context,
            plugin_config=plugin_config,
            target_urls=target_urls,
            logger=None
        )

    return _factory


@pytest.fixture
def responses_mock():
    """responses 라이브러리를 사용한 HTTP 모킹"""
    import responses as responses_lib
    with responses_lib.RequestsMock() as rsps:
        yield rsps
