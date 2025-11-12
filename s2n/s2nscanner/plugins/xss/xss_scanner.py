from __future__ import annotations

import html
import json
import time
import re
import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

import requests

if __package__ is None or __package__ == "":
    import sys as _sys

    APP_DIR = Path(__file__).resolve().parent
    ROOT_DIR = APP_DIR.parent.parent.parent
    for _path in (APP_DIR, ROOT_DIR):
        if str(_path) not in _sys.path:
            _sys.path.append(str(_path))

try:
    # 프로젝트에 정의된 공통 타입들이 있으면 사용
    from s2n.interfaces import (
        PluginContext,
        ScanContext,
        PluginConfig,
        Finding as S2NFinding,
        PluginResult,
        PluginStatus,
        Severity,
        Confidence,
        PluginError,
    )
except Exception:
    # 없을 경우에도 동작하도록 경량 대체 클래스 정의 (호환 목적)
    from types import SimpleNamespace

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

    class PluginError(SimpleNamespace):
        pass

    class S2NFinding(SimpleNamespace):
        pass

# 전용 로거 (CLI에서 핸들러/레벨을 설정)
logger = logging.getLogger("s2n_xss")

# CSRF 토큰, nonce 등을 탐지하기 위한 키워드 목록
TOKEN_KEYWORDS = ("token", "csrf", "nonce")
# 요청 타임아웃 설정 (초)
# 기존 DEFAULT_TIMEOUT(10초)을 5초로 단축
DEFAULT_TIMEOUT = 5
# User-Agent 헤더 값 설정
USER_AGENT = "s2n_xss/0.1.0 (Reflected Scanner)"
# 토큰 패턴 정규식 템플릿, HTML input 태그에서 특정 키워드가 포함된 name 속성과 value 값을 추출
TOKEN_PATTERN_TEMPLATE = (
    r'name=["\']([^"\']*{keyword}[^"\']*)["\']\s+value=["\']([^"\']+)["\']'
)


@dataclass
class PayloadResult:
    """
    페이로드 테스트 결과를 표현하는 데이터 클래스.
    - payload: 실제 삽입한 문자열
    - context: 반영된 컨텍스트(html/attribute/mixed/stored 등)
    - category: 취약점 유형 구분(reflected/stored)
    - description: 추가 설명 및 진단 근거
    """
    payload: str  # 테스트한 페이로드 문자열
    context: str  # 페이로드가 반영된 컨텍스트 (html, attribute 등)
    category: str  # 취약점 유형 (reflected, stored)
    category_ko: str  # 한글로 된 취약점 유형명
    description: str  # 상세 설명


@dataclass
class Finding:
    """
    특정 URL/파라미터 조합에서 발견된 취약점 정보를 수집한다.
    matches 리스트에 PayloadResult를 계속 추가하여 한 파라미터가 여러 페이로드에 취약할 때도 한눈에 볼 수 있다.
    """
    url: str  # 취약점이 발견된 URL
    parameter: str  # 취약점이 발견된 파라미터 이름
    method: str  # HTTP 메서드 (GET, POST)
    matches: List[PayloadResult] = field(
        default_factory=list
    )  # 성공한 페이로드 결과 리스트

    def as_dict(self) -> Dict:
        # Finding 객체를 딕셔너리 형태로 변환하여 반환
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "successful_payloads": [match.__dict__ for match in self.matches],
        }

    def as_s2n_finding(self):
        """
        변환 헬퍼: S2N 문서 기반 Finding 형태로 변환(간이)
        """
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "successful_payloads": [match.__dict__ for match in self.matches],
        }


@dataclass
class InputPoint:
    """
    URL 또는 HTML form으로부터 추출한 사용자 입력 지점을 표현한다.
    - url: 요청이 전송될 엔드포인트 (action 없이 form이면 현재 URL)
    - method: GET/POST
    - parameters: 기본값/토큰이 들어있는 파라미터 dict
    - source: 어디서 발견했는지(url/form/manual)를 기록해 디버깅에 활용
    """
    url: str  # 입력 지점 URL
    method: str  # HTTP 메서드
    parameters: Dict[str, str]  # 파라미터 이름과 기본값 딕셔너리
    source: str  # 입력 지점 출처 (url, form, manual)


class FormParser(HTMLParser):
    """
    HTML form과 내부 input 요소를 추출하기 위한 전용 파서.
    - form 시작 태그에서 action/method 초기화
    - input/textarea/select 요소를 순서대로 기록
    - 종료 태그(form) 시점에 지금까지 수집한 정보를 forms 리스트에 저장한다.
    """

    # HTML 파싱을 통해 form 태그와 그 내부의 input, textarea, select 필드를 추출하는 클래스

    def __init__(self):
        super().__init__()
        self.forms: List[Dict] = []  # 파싱된 폼 정보를 저장하는 리스트
        self._current: Optional[Dict] = None  # 현재 파싱 중인 폼 정보

    def handle_starttag(self, tag, attrs):
        # HTML 시작 태그 처리
        attrs_dict = dict(attrs)

        if tag == "form":
            # form 태그 시작 시 폼 정보 초기화
            self._current = {
                "action": attrs_dict.get("action", ""),  # 폼 제출 액션 URL
                "method": attrs_dict.get(
                    "method", "GET"
                ).upper(),  # 폼 제출 메서드 (기본 GET)
                "inputs": [],  # 폼 내부 입력 필드 리스트
            }
        elif tag in {"input", "textarea", "select"} and self._current is not None:
            # 폼 내부의 입력 필드 태그 처리
            name = attrs_dict.get("name", "")
            if not name:
                # name 속성이 없으면 무시
                return
            input_type = attrs_dict.get("type", "text").lower()
            # 입력 필드 정보를 현재 폼의 inputs 리스트에 추가
            self._current["inputs"].append(
                {
                    "type": input_type,
                    "name": name,
                    "value": attrs_dict.get("value", ""),
                }
            )

    def handle_endtag(self, tag):
        # HTML 종료 태그 처리
        if tag == "form" and self._current is not None:
            # form 태그 종료 시 현재 폼을 forms 리스트에 저장하고 초기화
            self.forms.append(self._current)
            self._current = None


class InputPointDetector:
    """
    URL 파라미터 및 HTML form 입력 필드를 동시에 탐지하는 도우미.
    - requests.Session 혹은 HttpClient 호환 객체를 받아 재사용한다.
    """

    # URL 쿼리 파라미터 및 HTML 폼 입력 필드를 탐지하여 입력 지점 리스트를 반환하는 클래스

    def __init__(self, transport: Any):
        """HttpClient/Session 객체를 받아 재사용한다."""
        self.transport = transport  # HttpClient 또는 requests.Session

    def detect(self, url: str) -> List[InputPoint]:
        """
        주어진 URL에서 사용자 입력이 가능한 포인트를 수집한다.
        1. URL 쿼리 파라미터를 파싱해 기본 GET 입력 포인트로 추가
        2. 실제 페이지를 요청해 form/input을 HTMLParser로 분석하여 action/method/필드 목록을 구성
        3. 토큰(hide) 필드도 그대로 parameters에 넣어 이후 요청 시 누락되지 않게 한다
        """
        # 입력 가능한 지점들을 탐지하는 메서드
        points: List[InputPoint] = []

        # URL 쿼리 파라미터 파싱
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        if url_params:
            # 쿼리 파라미터가 존재하면 첫 번째 값만 추출하여 파라미터 딕셔너리 생성
            params = {k: v[0] if isinstance(v, list) else v for k, v in url_params.items()}
            logger.info("[DETECT] Query parameters: %s", list(params.keys()))
            points.append(
                InputPoint(
                    url=parsed._replace(query="").geturl(),  # 쿼리 제거한 기본 URL
                    method="GET",
                    parameters=params,
                    source="url",
                )
            )
        else:
            logger.info("[DETECT] No query parameters detected")

        try:
            # 실제 페이지 요청 후 HTML 폼을 파싱하여 입력 필드 탐지
            response = self.transport.get(url, timeout=DEFAULT_TIMEOUT)
            if response.status_code == 200:
                parser = FormParser()
                parser.feed(response.text)
                for form in parser.forms:
                    params = {}
                    for field in form["inputs"]:
                        name = field["name"]
                        value = field["value"] or "test"  # 기본값이 없으면 'test'로 설정
                        field_type = field["type"].lower()

                        if field_type in {"submit", "button"}:
                            # submit, button 타입은 기본값 또는 이름을 파라미터 값으로 설정
                            params[name] = field["value"] or name
                            continue

                        if field_type == "hidden":
                            # hidden 필드는 value 값을 그대로 사용
                            params[name] = field["value"]
                        else:
                            # 기타 필드는 기본값 또는 'test' 사용
                            params[name] = value

                    if params:
                        action = form["action"]
                        # action이 비어있으면 현재 URL로 설정, 아니면 절대 URL로 변환
                        target = urljoin(url, action) if action else url
                        logger.info(
                            "[DETECT] Form detected: method=%s fields=%s",
                            form["method"],
                            list(params.keys()),
                        )
                        points.append(
                            InputPoint(
                                url=target,
                                method=form["method"],
                                parameters=params,
                                source="form",
                            )
                        )
        except Exception as exc:
            logger.warning("Failed to detect input points from %s: %s", url, exc)

        for idx, point in enumerate(points, 1):
            fields = list(point.parameters.keys())
            preview = fields[:5] + (["..."] if len(fields) > 5 else [])
            logger.info(
                "[DETECT] Input point #%d -> method=%s origin=%s fields=%s",
                idx,
                point.method,
                point.source,
                preview,
            )
        logger.info("[DETECT] Input point count: %d", len(points))

        return points


def update_tokens_from_html(html_content: str, params: Dict[str, str]) -> None:
    """
    응답 HTML에서 CSRF token/nonce 등 보호 필드를 찾아 params dict를 갱신한다.
    - TOKEN_KEYWORDS 를 포함한 input name / value를 정규식으로 찾고
    - 이 값을 params에 대입해 다음 요청 시 동일 토큰으로 재사용한다.
    """
    # HTML 내용에서 CSRF 토큰 등 보안 토큰을 찾아 파라미터 딕셔너리에 업데이트
    for keyword in TOKEN_KEYWORDS:
        pattern = re.compile(TOKEN_PATTERN_TEMPLATE.format(keyword=keyword))
        for match in pattern.finditer(html_content):
            field_name, value = match.groups()
            params[field_name] = value


def refresh_tokens(
    transport: Any, url: str, params: Dict[str, str], method: str
) -> None:
    """
    추가 HTTP 요청을 수행해 토큰 값을 최신 상태로 맞춘다.
    - GET 요청: params를 그대로 붙여 요청
    - POST 요청: data에 params를 실어 보냄
    - 응답 본문을 update_tokens_from_html() 에 전달하여 hidden field 변동에 대응한다.
    """
    # 요청을 보내고 응답에서 토큰 정보를 갱신하는 함수
    try:
        if method.upper() == "GET":
            response = transport.get(url, params=params, timeout=DEFAULT_TIMEOUT)
        else:
            response = transport.post(url, data=params, timeout=DEFAULT_TIMEOUT)
        response.encoding = response.apparent_encoding
        update_tokens_from_html(response.text, params)
    except Exception as exc:
        logger.warning("Failed to refresh tokens for %s (%s): %s", url, method, exc)


def extract_payloads(payloads_json: Dict) -> List[str]:
    """
    페이로드 JSON 구조 내 모든 문자열을 재귀적으로 모아서 1차원 리스트로 만든다.
    - payloads / filter_bypass / korean_encoding_specific 등 섹션을 전부 순회
    - 값이 문자열인 경우만 리스트에 추가하여 이후 반복문에서 바로 사용할 수 있도록 한다.
    """
    # JSON 구조에서 페이로드 문자열들을 재귀적으로 수집하는 함수
    collected: List[str] = []

    def walk(node):
        # 재귀적으로 리스트, 딕셔너리, 문자열을 탐색하여 페이로드 수집
        if isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, str):
            collected.append(node)

    # 주요 섹션별로 페이로드 수집
    walk(payloads_json.get("payloads", {}))
    walk(payloads_json.get("filter_bypass", {}))
    walk(payloads_json.get("korean_encoding_specific", {}))
    # 빈 문자열 필터링 후 반환
    return [payload for payload in collected if payload]


class ReflectedScanner:
    """
    반사형 및 저장형 XSS 취약점을 탐지하는 핵심 엔진.
    - payload 파일을 읽어 테스트 목록을 구성하고 InputPointDetector로 입력 지점을 찾는다.
    - 외부에서 주입된 HttpClient만 사용해 session guide의 “공용 세션” 규약을 지킨다.
    - run()은 PluginContext를 입력 받아 interfaces.PluginResult/Finding을 반환해
      interfaces.py에서 정의한 단계(PluginContext → Finding → PluginResult)를 그대로 따른다.
    """

    def __init__(
        self,
        payloads_path: Path,
        http_client: Any,
        cookies: Optional[Dict[str, str]] = None,
    ):
        # 초기화: 페이로드 로드, 세션 설정, 입력 지점 탐지기 생성
        if http_client is None:
            raise ValueError("ReflectedScanner requires an injected HttpClient/transport.")
        self.transport = http_client

        self.session = getattr(self.transport, "s", None)
        if self.session is None and isinstance(self.transport, requests.Session):
            self.session = self.transport

        if self.session is not None:
            self.session.headers.update({"User-Agent": USER_AGENT})
            if cookies:
                self.session.cookies.update(cookies)
        elif cookies:
            logger.warning("Unable to inject cookies — no session object available.")

        # 페이로드 JSON 파일 로드
        with payloads_path.open("r", encoding="utf-8") as fp:
            payloads_json = json.load(fp)

        # 페이로드 리스트 추출
        self.payloads: List[str] = extract_payloads(payloads_json)
        self.detector = InputPointDetector(self.transport)
        self.findings: Dict[str, Finding] = {}
        # 통계
        self._requests_sent = 0
        self._urls_scanned = 0

    # ---------------------------------------------------------------------
    # New API: run(plugin_context) -> PluginResult
    # This method follows the S2N common-types pattern: it expects a PluginContext
    # that contains scan_context (with http_client) and plugin_config.
    # It will reuse an injected http_client when available (to preserve login/session).
    # ---------------------------------------------------------------------
    def run(self, context: PluginContext) -> PluginResult:
        """
        PluginContext 기반으로 XSS 스캔을 수행해 PluginResult를 만든다.
        - interfaces.PluginContext → PluginResult 흐름(session guide)과 동일하게,
          scan_context/http_client/target_urls를 읽어 입력 포인트 탐지 → 페이로드 주입을 수행한다.
        - 성공 페이로드는 내부 Finding map에 누적 후 interfaces.Finding dataclass로 변환한다.
        - 예외 발생 시 PluginError를 기록해 PluginResult.error로 전달한다.
        """
        start_dt = datetime.now(timezone.utc)
        self.findings.clear()
        self._requests_sent = 0
        self._urls_scanned = 0

        # Prefer http_client from provided scan_context to preserve session/cookies.
        http_client = getattr(getattr(context, "scan_context", None), "http_client", None)
        if http_client is None:
            http_client = self.transport

        # PluginConfig 미설정 시 기본값을 덮어씁니다 (max_payloads=50, timeout=5)
        plugin_cfg = getattr(context, "plugin_config", None) or PluginConfig(
            enabled=True,
            timeout=5,
            max_payloads=50,
            custom_params={},
        )
        max_payloads = getattr(plugin_cfg, "max_payloads", 50)
        timeout = getattr(plugin_cfg, "timeout", 5)

        target_urls = list(getattr(context, "target_urls", None) or [])
        if not target_urls:
            scan_cfg = getattr(getattr(context, "scan_context", None), "config", None)
            if scan_cfg and getattr(scan_cfg, "target_url", None):
                target_urls.append(scan_cfg.target_url)

        status = getattr(PluginStatus, "SUCCESS", "success")
        plugin_error = None

        if not target_urls:
            status = getattr(PluginStatus, "SKIPPED", "skipped")
        else:
            try:
                for point_url in target_urls:
                    self._urls_scanned += 1
                    points = []
                    # reuse detector logic but with provided http_client
                    detector = InputPointDetector(http_client)
                    points = detector.detect(point_url)

                    # 입력 포인트별 최초 1회만 토큰을 갱신해 토큰 보호를 강화
                    for p in points:
                        try:
                            refresh_tokens(http_client, p.url, p.parameters, p.method)
                        except Exception as exc:
                            logger.warning("[TOKEN] Failed initial token refresh: %s", exc)

                    if not points:
                        # if no input points found, create a default inputpoint for url itself
                        parsed = urlparse(point_url)
                        points = [
                            InputPoint(
                                url=point_url.split("?")[0],
                                method="GET",
                                parameters=parse_qs(parsed.query) or {},
                                source="url",
                            )
                        ]

                    for point in points:
                        for param_name in list(point.parameters.keys()):
                            lower = param_name.lower()
                            if any(k in lower for k in TOKEN_KEYWORDS):
                                continue

                            payloads = self.payloads
                            if max_payloads:
                                payloads = payloads[: max_payloads]

                            for payload in payloads:
                                try:
                                    self._requests_sent += 1
                                    # honor timeout from plugin config
                                    if point.method.upper() == "POST":
                                        response = http_client.post(
                                            point.url,
                                            data={**point.parameters, param_name: payload},
                                            timeout=timeout,
                                        )
                                    else:
                                        response = http_client.get(
                                            point.url,
                                            params={**point.parameters, param_name: payload},
                                            timeout=timeout,
                                        )
                                    response.encoding = response.apparent_encoding
                                    body = response.text

                                    # token refresh attempt
                                    update_tokens_from_html(body, point.parameters)

                                    if payload in body:
                                        pr = PayloadResult(
                                            payload=payload,
                                            context=self._detect_context(body, payload),
                                            category="reflected",
                                            category_ko="반사형",
                                            description="Payload echoed without encoding",
                                        )
                                        self._record(point, param_name, pr)
                                except Exception as exc:
                                    logger.debug(
                                        "Request error for %s %s: %s",
                                        point.url,
                                        param_name,
                                        exc,
                                    )
                                    continue
            except Exception as exc:  # noqa: BLE001
                status = getattr(PluginStatus, "FAILED", "failed")
                plugin_error = PluginError(
                    error_type=type(exc).__name__,
                    message=str(exc),
                    traceback=None,
                    context={"target_urls": target_urls},
                )
                logger.exception("XSS scanner error: %s", exc)

        end_dt = datetime.now(timezone.utc)
        s2n_findings = self._as_s2n_findings()
        metadata = {"payloads_tried": len(self.payloads)}
        if status == getattr(PluginStatus, "SUCCESS", "success") and not s2n_findings:
            metadata["note"] = "No reflected/stored XSS detected"

        plugin_result = PluginResult(
            plugin_name=getattr(context, "plugin_name", "xss"),
            status=status,
            findings=s2n_findings,
            start_time=start_dt,
            end_time=end_dt,
            duration_seconds=(end_dt - start_dt).total_seconds(),
            urls_scanned=self._urls_scanned,
            requests_sent=self._requests_sent,
            error=plugin_error,
            metadata=metadata,
        )
        return plugin_result

    def _test_stored(self, point: InputPoint) -> Optional[PayloadResult]:
        """
        저장형 XSS 여부를 단일 InputPoint 기준으로 검사한다.
        - hidden/token 필드와 버튼 필드는 건드리지 않고 다른 필드 전체에 스토어드 페이로드 삽입
        - 제출 후 토큰을 갱신하고 잠시 대기
        - 동일 URL을 다시 요청해 페이로드가 반영됐는지 확인하여 PayloadResult를 반환
        """
        # 저장형 XSS 테스트 함수
        params = point.parameters.copy()
        unique_tag = (
            f"s2n_stored_{int(time.time())}"  # 고유 태그 생성 (타임스탬프 기반)
        )
        payload = f"<script>alert('{unique_tag}')</script>"  # 저장형 페이로드

        # Token 강화 모드: 매 페이로드 refresh 제거 (detect 시 최초 1회만)

        updated = False
        for name in list(params.keys()):
            lower = name.lower()
            # 토큰 관련 파라미터 및 버튼 관련 파라미터는 건너뜀
            if any(keyword in lower for keyword in TOKEN_KEYWORDS):
                continue
            if lower in {"btnsign", "btnsubmit", "btnclear", "submit"}:
                continue
            # 페이로드로 파라미터 값 변경
            params[name] = payload
            updated = True

        if not updated:
            # 변경된 파라미터가 없으면 테스트 불가
            return None

        try:
            # 저장형 페이로드 전송 (POST/GET)
            if point.method.upper() == "POST":
                response = self.transport.post(
                    point.url, data=params, timeout=DEFAULT_TIMEOUT
                )
            else:
                response = self.transport.get(
                    point.url, params=params, timeout=DEFAULT_TIMEOUT
                )
            response.encoding = response.apparent_encoding
            # 응답에서 토큰 갱신
            update_tokens_from_html(response.text, params)
        except Exception as exc:
            logger.warning("Stored payload submit failed for %s: %s", point.url, exc)
            return None

        # 저장형 XSS가 반영되기까지 대기
        time.sleep(0.8)

        try:
            # 저장된 페이로드가 반영되었는지 확인하기 위해 다시 요청
            verify = self.transport.get(point.url, timeout=DEFAULT_TIMEOUT)
            verify.encoding = verify.apparent_encoding
            body = verify.text
            escaped = html.escape(payload)
            # 페이로드 또는 고유 태그가 응답에 포함되어 있는지 검사
            if payload in body or unique_tag in body or escaped in body:
                return PayloadResult(
                    payload=payload,
                    context="stored",
                    category="stored",
                    category_ko="저장형",
                    description="Payload persisted and reflected on subsequent view",
                )
        except Exception as exc:
            logger.warning(
                "Stored payload verification failed for %s: %s", point.url, exc
            )
            return None

        return None

    def _test_payload(
        self, point: InputPoint, param_name: str, payload: str
    ) -> Optional[PayloadResult]:
        """
        반사형 XSS를 위해 단일 파라미터에 페이로드를 주입한다.
        - point.parameters를 복사해 해당 param_name만 payload로 교체
        - transport 요청 이후 응답 본문에서 payload 문자열이 그대로 나타나는지 검사
        - 컨텍스트(HTML/attribute/mixed)를 추론하여 PayloadResult에 포함한다.
        """
        # 반사형 XSS 테스트 함수
        params = point.parameters.copy()
        params[param_name] = payload  # 테스트할 파라미터에 페이로드 삽입

        # Token 강화 모드: detect 단계에서만 토큰을 갱신하므로 여기서는 추가 호출을 생략
        try:
            # 요청 전송 (POST/GET)
            if point.method.upper() == "POST":
                response = self.transport.post(
                    point.url, data=params, timeout=DEFAULT_TIMEOUT
                )
            else:
                response = self.transport.get(
                    point.url, params=params, timeout=DEFAULT_TIMEOUT
                )

            response.encoding = response.apparent_encoding
            body = response.text

            # 응답에서 토큰 갱신
            update_tokens_from_html(body, params)

            # 페이로드가 응답에 포함되어 있지 않으면 실패
            if payload not in body:
                return None

            # 페이로드가 포함된 컨텍스트 탐지
            context = self._detect_context(body, payload)
            return PayloadResult(
                payload=payload,
                context=context,
                category="reflected",
                category_ko="반사형",
                description="Payload echoed without encoding",
            )
        except Exception as exc:
            logger.exception(
                "Reflected payload test failed (%s %s=%s): %s",
                point.url,
                param_name,
                payload,
                exc,
            )
            return None

    @staticmethod
    def _detect_context(body: str, payload: str) -> str:
        # 페이로드가 포함된 컨텍스트를 탐지하는 정적 메서드
        escaped = html.escape(payload)
        # 속성 값 내에 페이로드가 포함되어 있는지 검사
        if f'="{payload}"' in body or f"='{payload}'" in body:
            return "attribute"
        # 페이로드가 원본과 이스케이프된 형태 모두 포함되어 있으면 'mixed' 컨텍스트
        if payload in body and escaped in body:
            return "mixed"
        # 그 외는 일반 html 컨텍스트로 간주
        return "html"

    def _record(
        self, point: InputPoint, param_name: str, result: PayloadResult
    ) -> None:
        """
        성공한 페이로드를 포인트+파라미터 기준으로 누적한다.
        - 동일 URL/파라미터/메서드 조합은 하나의 Finding으로 묶어 matches 리스트를 채운다.
        """
        # 반사형 취약점 결과를 findings 딕셔너리에 기록
        key = f"{point.url}|{param_name}|{point.method}"
        finding = self.findings.get(key)
        if not finding:
            finding = Finding(url=point.url, parameter=param_name, method=point.method)
            self.findings[key] = finding
        finding.matches.append(result)

    def _record_stored(self, point: InputPoint, result: PayloadResult) -> None:
        """저장형 결과를 별도의 key([stored])로 기록해 혼동을 막는다."""
        # 저장형 취약점 결과를 findings 딕셔너리에 기록
        key = f"{point.url}|[stored]|{point.method}"
        finding = self.findings.get(key)
        if not finding:
            finding = Finding(url=point.url, parameter="[stored]", method=point.method)
            self.findings[key] = finding
        finding.matches.append(result)

    def _as_s2n_findings(self) -> List[S2NFinding]:
        """
        내부 Finding dict를 s2n.interfaces.Finding 리스트로 변환한다.
        - matches 통계를 요약해 description과 evidence를 구성
        - severity/confidence는 기본값(HIGH/FIRM)으로 설정하되 필요 시 조정 가능
        """
        results: List[S2NFinding] = []
        severity_high = getattr(Severity, "HIGH", "HIGH")
        confidence_val = getattr(Confidence, "FIRM", "FIRM")
        for idx, finding in enumerate(self.findings.values(), start=1):
            first_match = finding.matches[0] if finding.matches else None
            payload = first_match.payload if first_match else None
            contexts = Counter(match.context for match in finding.matches)
            context_summary = ", ".join(f"{ctx}:{cnt}" for ctx, cnt in contexts.items())
            description = (
                f"{len(finding.matches)} payload(s) reflected in contexts [{context_summary}]"
                if context_summary
                else "Payload reflected without encoding"
            )
            evidence = first_match.description if first_match else None
            results.append(
                S2NFinding(
                    id=f"xss-{idx}",
                    plugin="xss",
                    severity=severity_high,
                    title="Cross-Site Scripting Detected",
                    description=description,
                    url=finding.url,
                    parameter=finding.parameter,
                    method=finding.method,
                    payload=payload,
                    evidence=evidence,
                    confidence=confidence_val,
                    timestamp=datetime.now(timezone.utc),
                )
            )
        return results
