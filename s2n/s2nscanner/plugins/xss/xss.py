from __future__ import annotations

import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# 모듈 경로/의존성 로딩
# ---------------------------------------------------------------------------
# 패키지로 import되는 경우와 CLI로 직접 실행되는 경우 모두 지원하기 위해
# __package__ 여부에 따라 상대경로를 보정하고 필요한 모듈을 동적으로 로드한다.
if __package__ is None or __package__ == "":
    APP_DIR = Path(__file__).resolve().parent
    ROOT_DIR = APP_DIR.parent.parent.parent
    for _path in (APP_DIR, ROOT_DIR):
        if str(_path) not in sys.path:
            sys.path.append(str(_path))
    from xss_scanner import ReflectedScanner  # type: ignore
    from s2n.s2nscanner.http.client import HttpClient  # type: ignore
else:
    from .xss_scanner import ReflectedScanner
    from ...http.client import HttpClient

# s2n.interfaces 모듈이 배포 환경에 존재하면 그 타입을 사용하고,
# 로컬 개발/테스트 중 모듈이 없을 때는 SimpleNamespace로
# PluginContext → PluginResult 흐름을 유지한다.
try:
    from s2n.s2nscanner.interfaces import (
        ScanConfig,
        ScanContext,
        PluginConfig,
        PluginContext,
        PluginResult,
    )
except Exception:  # pragma: no cover
    from types import SimpleNamespace

    class PluginConfig(SimpleNamespace):
        """플러그인 전용 설정이 아직 정식 타입이 아닐 때 사용하는 임시 구조체."""

        pass

    class ScanConfig(SimpleNamespace):
        """ScanConfig 대체: 최소한 target_url 속성만 유지해 실행을 가능하게 한다."""

        def __init__(self, target_url: str, **kwargs):
            super().__init__(target_url=target_url, **kwargs)

    class ScanContext(SimpleNamespace):
        """ScanContext 대체: scan_id, 시작시각, HttpClient 등을 담아 플러그인이 참고할 수 있게 한다."""

        def __init__(self, scan_id: str, start_time: datetime, config, http_client, crawler=None, **kwargs):
            super().__init__(
                scan_id=scan_id,
                start_time=start_time,
                config=config,
                http_client=http_client,
                crawler=crawler,
                **kwargs,
            )

    class PluginContext(SimpleNamespace):
        """PluginContext 대체: 플러그인 이름, 컨텍스트, 설정 등을 포괄."""

        pass

    class PluginResult(SimpleNamespace):
        """PluginResult 대체: findings, status 등을 최소한으로 전달하기 위한 구조체."""

        pass


LOGGER = logging.getLogger("s2n.plugins.xss")


def _prompt(message: str) -> str:
    """
    사용자 입력을 안전하게 받아오는 헬퍼.
    - Ctrl+C, Ctrl+D 등으로 입력이 중단되면 깔끔하게 종료해 CLI가 그대로 멈추지 않도록 함.
    - CLI 실행 시 반복적으로 사용되므로 별도로 추출하였다.
    """
    try:
        return input(message)
    except (KeyboardInterrupt, EOFError):
        print("\nAborted by user.")
        sys.exit(0)


def _load_payload_path() -> Path:
    """
    ReflectedScanner가 사용할 페이로드 파일(xss_payloads.json)을 찾는다.
    - xss.py와 동일한 디렉터리에서 검색하며, 없으면 즉시 예외를 발생시킨다.
    """
    payload_name = "xss_payloads.json"
    script_path = Path(__file__).parent / payload_name
    if script_path.exists():
        return script_path

    raise FileNotFoundError(f"Payload file not found: {payload_name}")


def _parse_cookies(raw: str) -> Dict[str, str]:
    """
    CLI에서 한 줄로 입력받은 쿠키 문자열을 requests가 이해할 수 있는 dict로 변환한다.
    "a=1; b=2" 형식을 "a": "1", "b": "2" 로 풀어 세션 객체에 주입한다.
    """
    cookies: Dict[str, str] = {}
    for pair in raw.split(";"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


def _finding_to_dict(finding: Any) -> Dict[str, Any]:
    """
    PluginResult 안의 Finding dataclass를 JSON 직렬화가 쉬운 dict로 변환한다.
    - dataclass가 아닐 수도 있어 getattr를 사용해 최대한 유연하게 접근.
    - Severity Enum → 문자열, timestamp → ISO 문자열로 풀어서 저장 파일이 간결해진다.
    """
    data = {
        "id": getattr(finding, "id", None),
        "plugin": getattr(finding, "plugin", "xss"),
        "severity": getattr(getattr(finding, "severity", None), "value", None)
        if hasattr(getattr(finding, "severity", None), "value")
        else getattr(finding, "severity", None),
        "title": getattr(finding, "title", ""),
        "description": getattr(finding, "description", ""),
        "url": getattr(finding, "url", None),
        "parameter": getattr(finding, "parameter", None),
        "method": getattr(finding, "method", None),
        "payload": getattr(finding, "payload", None),
        "evidence": getattr(finding, "evidence", None),
    }
    timestamp = getattr(finding, "timestamp", None)
    if timestamp:
        data["timestamp"] = timestamp.isoformat() if hasattr(timestamp, "isoformat") else timestamp
    return data


class XSSPlugin:
    """
    Reflected/Stored XSS 취약점 탐지 플러그인.
    - PluginContext를 입력으로 받아 ReflectedScanner.run()을 호출하고
      interfaces.PluginResult를 그대로 반환한다.
    - CLI도 동일 인스턴스를 사용해 사용자 I/O와 실제 스캐너 로직을 분리한다.
    """
    name = "xss"
    description = "Detects Reflected/Stored Cross-Site Scripting vulnerabilities."

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        플러그인 인스턴스를 초기화한다.
        - config dict로 페이로드 경로나 동작 옵션을 주입할 수 있다.
        - payload_path는 기본적으로 현재/모듈 경로에서 자동 검색된다.
        """
        self.config = config or {}
        self.payload_path = Path(self.config.get("payload_path", _load_payload_path()))

    def _build_scanner(self, http_client: Optional[Any] = None) -> ReflectedScanner:
        """
        ReflectedScanner를 생성한다.
        - Scanner 엔진이 넘겨준 HttpClient를 그대로 연결해 로그인 세션, 헤더 등을 재사용한다.
        - session guide가 요구하는 “공용 HttpClient 주입” 원칙을 따르며,
          HttpClient가 없으면 즉시 예외를 발생시켜 실행 단계에서 문제를 발견한다.
        """
        if http_client is None:
            raise ValueError("XSSPlugin requires scan_context.http_client to be provided.")
        return ReflectedScanner(self.payload_path, http_client=http_client)

    def run(self, plugin_context: PluginContext) -> PluginResult:
        """
        스캐너 엔진이 호출하는 표준 엔트리.
        - PluginContext.scan_context에 담긴 http_client / target_url을 읽어 ReflectedScanner에 전달한다.
        - 결과는 interfaces.PluginResult 형식으로 반환되어 ScanReport 단계에서 그대로 사용된다.
        """
        scan_ctx = plugin_context.scan_context
        http_client = getattr(scan_ctx, "http_client", None)
        scanner = self._build_scanner(http_client=http_client)

        if not getattr(plugin_context, "target_urls", None):
            default_url = getattr(scan_ctx.config, "target_url", None)
            if default_url:
                plugin_context.target_urls = [default_url]

        return scanner.run(plugin_context)


def main(config: Optional[Dict[str, Any]] = None) -> XSSPlugin:
    """
    스캐너 엔진이 import 후 호출하는 팩토리.
    - config를 전달하면 개별 플러그인 인스턴스가 생성된다.
    """
    return XSSPlugin(config)


def cli() -> int:
    """
    터미널에서 직접 사용할 수 있는 간이 CLI 진입점.
    - 사용자 입력으로 타깃 URL과 쿠키를 받고
    - 공유 HttpClient와 PluginContext를 구성하여 플러그인을 그대로 실행
    - 결과 요약 및 JSON 저장을 지원한다.
    """
    logger = LOGGER
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    try:
        payload_path = _load_payload_path()
    except FileNotFoundError as exc:
        print(exc)
        return 1

    print("=" * 70)
    print("s2n_xss - Reflected XSS Vulnerability Scanner")
    print("=" * 70)

    target_url = _prompt("\n[>] Enter target URL: ").strip()
    if not target_url:
        print("No target provided.")
        return 1

    client = HttpClient()
    cookies_input = _prompt("[>] Enter cookies (key=value;key2=value2) or blank: ").strip()
    cookies: Optional[Dict[str, str]] = None
    if cookies_input:
        cookies = _parse_cookies(cookies_input)
        jar = getattr(client, "cookies", None) or getattr(getattr(client, "s", None), "cookies", None)
        if jar is not None:
            jar.update(cookies)

    plugin = XSSPlugin({"payload_path": str(payload_path)})
    plugin_cfg = PluginConfig(enabled=True, timeout=10, max_payloads=None, custom_params={})
    scan_cfg = ScanConfig(target_url=target_url)
    scan_ctx = ScanContext(
        scan_id=f"cli-{int(time.time())}",
        start_time=datetime.now(timezone.utc),
        config=scan_cfg,
        http_client=client,
        crawler=None,
    )
    plugin_ctx = PluginContext(
        plugin_name=plugin.name,
        scan_context=scan_ctx,
        plugin_config=plugin_cfg,
        target_urls=[target_url],
        logger=logger,
    )

    try:
        result = plugin.run(plugin_ctx)
    except Exception as exc:  # noqa: BLE001
        logger.exception("XSS plugin run failed: %s", exc)
        return 1

    findings = [ _finding_to_dict(f) for f in getattr(result, "findings", []) ]
    if findings:
        print(f"\n⚠️  Detected {len(findings)} reflected/stored XSS finding(s):")
        for idx, finding in enumerate(findings, 1):
            print(f"[{idx}] {finding.get('url')} ({finding.get('method')}) param={finding.get('parameter')}")
    else:
        print("\n✅ No reflected/stored XSS detected.")

    return 0


if __name__ == "__main__":
    sys.exit(cli())
