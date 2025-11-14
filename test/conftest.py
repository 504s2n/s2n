# conftest.py
import sys
import json
import pytest
from pathlib import Path
import shutil


# ========================================
# 1. 프로젝트 루트 동적 탐색
# ========================================
def find_project_root(start_path=None):
    """
    .git 또는 pyproject.toml을 찾아 프로젝트 루트 반환
    테스트 파일 위치가 바뀌어도 안정적
    """
    if start_path is None:
        start_path = Path(__file__).resolve()

    current = Path(start_path)

    while current != current.parent:
        if (current / ".git").exists() or (current / "pyproject.toml").exists():
            return current
        current = current.parent

    # fallback: 현재 파일 기준 상위
    return Path(start_path).resolve().parent


PROJECT_ROOT = find_project_root()


# ========================================
# 2. sys.path 자동 보정
# ========================================
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ========================================
# 3. 페이로드 파일 동적 탐색
# ========================================
def find_payload_file(filename="xss_payloads.json"):
    """
    xss_payloads.json을 프로젝트에서 찾기
    1. 예상 경로 우선 확인 (빠름)
    2. 없으면 전체 검색 (느리지만 확실)
    """
    # 예상 경로들 (구조 변경 대비)
    expected_paths = [
        PROJECT_ROOT / "s2n" / "s2nscanner" / "plugins" / "xss" / filename,
        PROJECT_ROOT / "s2n" / "plugins" / "xss" / filename,
        PROJECT_ROOT / "plugins" / "xss" / filename,
    ]

    for path in expected_paths:
        if path.exists():
            return path

    # 전체 검색 (최후 수단)
    for path in PROJECT_ROOT.rglob(filename):
        if path.is_file():
            return path

    return None


# ========================================
# 4. Import 절대경로 사용
# ========================================
try:
    from s2n.s2nscanner.interfaces import (
        PluginContext, ScanContext, PluginConfig,
        PluginResult, PluginStatus, Severity, Confidence,
        ScanConfig
    )
    from s2n.s2nscanner.http.client import HttpClient
    HAS_INTERFACES = True
except ImportError:
    # fallback
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
        PARTIAL = "partial"

    class Severity:
        HIGH = "HIGH"

    class Confidence:
        FIRM = "firm"

    class ScanConfig(SimpleNamespace):
        pass

    import requests

    class HttpClient:
        def __init__(self):
            self.s = requests.Session()

        def get(self, *args, **kwargs):
            return self.s.get(*args, **kwargs)

        def post(self, *args, **kwargs):
            return self.s.post(*args, **kwargs)


# test_xss_fixtures 절대경로 import
from test_xss_fixtures import SAMPLE_PAYLOADS_JSON


# ========================================
# 5. Fixtures
# ========================================
@pytest.fixture(scope="session")
def sample_payloads():
    """테스트용 페이로드 리스트"""
    from test_xss_fixtures import SAMPLE_PAYLOADS
    return SAMPLE_PAYLOADS


@pytest.fixture(scope="session")
def payload_path(tmp_path_factory):
    """
    실제 xss_payloads.json을 동적으로 찾아 임시 경로에 복사
    경로 구조가 바뀌어도 작동
    """
    real_payload = find_payload_file("xss_payloads.json")

    tmp_dir = tmp_path_factory.mktemp("xss")
    tmp_payload = tmp_dir / "xss_payloads.json"

    if real_payload and real_payload.exists():
        shutil.copy(real_payload, tmp_payload)
    else:
        # fallback: 샘플 데이터 생성
        tmp_payload.write_text(
            json.dumps(SAMPLE_PAYLOADS_JSON, ensure_ascii=False),
            encoding="utf-8"
        )

    return tmp_payload


@pytest.fixture
def mock_http_client():
    """HttpClient wrapper 모킹"""
    client = HttpClient()
    return client


@pytest.fixture
def plugin_context_factory(mock_http_client):
    """PluginContext 생성 헬퍼"""
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
    """responses 라이브러리 HTTP 모킹"""
    responses_lib = pytest.importorskip("responses")
    with responses_lib.RequestsMock() as rsps:
        yield rsps
