from __future__ import annotations

import html
import json
import time
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

import requests

from s2n.s2nscanner.interfaces import (
    Confidence,
    Finding as S2NFinding,
    PluginConfig,
    PluginContext,
    PluginError,
    PluginResult,
    PluginStatus,
    Severity,
)
from s2n.s2nscanner.logger import get_logger


logger = get_logger("plugins.xss")

# 토큰 탐지를 위한 키워드 목록
TOKEN_KEYWORDS = ("token", "csrf", "nonce")
DEFAULT_TIMEOUT = 5
USER_AGENT = "s2n_xss/0.1.0 (Reflected Scanner)"

TOKEN_PATTERN_TEMPLATE = (
    r'name=["\']([^"\']*{keyword}[^"\']*)["\']\s+value=["\']([^"\']+)["\']'
)


# 페이로드 테스트 결과
@dataclass
class PayloadResult:
    payload: str
    context: str
    category: str
    category_ko: str
    description: str


# 취약점 발견 정보
@dataclass
class Finding:
    url: str
    parameter: str
    method: str
    matches: List[PayloadResult] = field(default_factory=list)

    def as_dict(self) -> Dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "successful_payloads": [match.__dict__ for match in self.matches],
        }

    def as_s2n_finding(self):
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "successful_payloads": [match.__dict__ for match in self.matches],
        }


# 사용자 입력 지점
@dataclass
class InputPoint:
    url: str
    method: str
    parameters: Dict[str, str]
    source: str


# HTML form 파서
class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: List[Dict] = []
        self._current: Optional[Dict] = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == "form":
            self._current = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag in {"input", "textarea", "select"} and self._current is not None:
            name = attrs_dict.get("name", "")
            if not name:
                return
            input_type = attrs_dict.get("type", "text").lower()
            self._current["inputs"].append(
                {
                    "type": input_type,
                    "name": name,
                    "value": attrs_dict.get("value", ""),
                }
            )

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


# 입력 포인트 탐지기
class InputPointDetector:
    """Input point detector for URL parameters and HTML forms"""

    def __init__(self, transport: Any):
        """HttpClient/Session 객체 주입"""
        self.transport = transport

    def detect(self, url: str) -> List[InputPoint]:
        """URL에서 입력 포인트 탐지 (쿼리 파라미터 + HTML 폼)"""
        points: List[InputPoint] = []

        # URL 쿼리 파라미터 파싱
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        if url_params:
            # 쿼리 파라미터가 존재하면 첫 번째 값만 추출하여 파라미터 딕셔너리 생성
            params = {
                k: v[0] if isinstance(v, list) else v for k, v in url_params.items()
            }
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
                        value = (
                            field["value"] or "test"
                        )  # 기본값이 없으면 'test'로 설정
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


# 토큰 갱신 유틸리티
def update_tokens_from_html(html_content: str, params: Dict[str, str]) -> None:
    for keyword in TOKEN_KEYWORDS:
        pattern = re.compile(TOKEN_PATTERN_TEMPLATE.format(keyword=keyword))
        for match in pattern.finditer(html_content):
            field_name, value = match.groups()
            params[field_name] = value


def refresh_tokens(
    transport: Any, url: str, params: Dict[str, str], method: str
) -> None:
    try:
        if method.upper() == "GET":
            response = transport.get(url, params=params, timeout=DEFAULT_TIMEOUT)
        else:
            response = transport.post(url, data=params, timeout=DEFAULT_TIMEOUT)
        response.encoding = response.apparent_encoding
        update_tokens_from_html(response.text, params)
    except Exception as exc:
        logger.warning("Failed to refresh tokens for %s (%s): %s", url, method, exc)


# 페이로드 추출 유틸리티
def extract_payloads(payloads_json: Dict) -> List[str]:
    collected: List[str] = []

    def walk(node):
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


# Reflected XSS 스캐너
class ReflectedScanner:
    def __init__(
        self,
        payloads_path: Path,
        http_client: Any,
        cookies: Optional[Dict[str, str]] = None,
    ):
        if http_client is None:
            raise ValueError(
                "ReflectedScanner requires an injected HttpClient/transport."
            )

        self.transport = http_client
        self._setup_session(http_client, cookies)
        self.payloads = self._load_payloads(payloads_path)
        self.detector = InputPointDetector(self.transport)
        self.findings: Dict[str, Finding] = {}
        self._requests_sent = 0
        self._urls_scanned = 0

    def _setup_session(
        self, http_client: Any, cookies: Optional[Dict[str, str]]
    ) -> None:
        self.session = getattr(http_client, "s", None)
        if self.session is None and isinstance(http_client, requests.Session):
            self.session = http_client

        if self.session is not None:
            self.session.headers.update({"User-Agent": USER_AGENT})
            if cookies:
                self.session.cookies.update(cookies)
        elif cookies:
            logger.warning("쿠키 주입 실패 - session 객체 없음")

    def _load_payloads(self, payloads_path: Path) -> List[str]:
        with payloads_path.open("r", encoding="utf-8") as fp:
            payloads_json = json.load(fp)
        return extract_payloads(payloads_json)

    def _reset_state(self) -> None:
        self.findings.clear()
        self._requests_sent = 0
        self._urls_scanned = 0

    def _extract_config(self, context: PluginContext) -> dict:
        # http_client: scan_context에서 우선 추출, 없으면 기본 transport 사용
        http_client = getattr(
            getattr(context, "scan_context", None), "http_client", None
        )
        if http_client is None:
            http_client = self.transport

        # plugin_config: 없으면 기본값 사용
        plugin_cfg = getattr(context, "plugin_config", None) or PluginConfig(
            enabled=True,
            timeout=5,
            max_payloads=50,
            custom_params={},
        )

        return {
            "http_client": http_client,
            "max_payloads": getattr(plugin_cfg, "max_payloads", 50),
            "timeout": getattr(plugin_cfg, "timeout", 5),
        }

    def _extract_target_urls(self, context: PluginContext) -> List[str]:
        """PluginContext에서 타겟 URL 목록 추출"""
        target_urls = getattr(context, "target_urls", None) or []
        if not target_urls:
            scan_cfg = getattr(getattr(context, "scan_context", None), "config", None)
            if scan_cfg and getattr(scan_cfg, "target_url", None):
                target_urls.append(scan_cfg.target_url)
        return target_urls

    def _should_skip_param(self, param_name: str) -> bool:
        return any(k in param_name.lower() for k in TOKEN_KEYWORDS)

    def _detect_input_points(self, url: str, http_client: Any) -> List[InputPoint]:
        detector = InputPointDetector(http_client)
        points = detector.detect(url)

        # 입력 포인트가 없으면 기본 URL 사용
        if not points:
            parsed = urlparse(url)
            points = [
                InputPoint(
                    url=url.split("?")[0],
                    method="GET",
                    parameters=parse_qs(parsed.query) or {},
                    source="url",
                )
            ]
        return points

    def _refresh_input_point_tokens(
        self, points: List[InputPoint], http_client: Any
    ) -> None:
        for p in points:
            try:
                refresh_tokens(http_client, p.url, p.parameters, p.method)
            except Exception as exc:
                logger.warning("[TOKEN] 토큰 갱신 실패: %s", exc)

    def _test_payload_on_param(
        self,
        point: InputPoint,
        param_name: str,
        payload: str,
        http_client: Any,
        timeout: int,
    ) -> None:
        try:
            self._requests_sent += 1

            # HTTP 요청 전송
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

            # 토큰 갱신 시도
            update_tokens_from_html(body, point.parameters)

            # 페이로드 반영 확인
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
            logger.debug("요청 에러 %s %s: %s", point.url, param_name, exc)

    def _scan_parameter(
        self,
        point: InputPoint,
        param_name: str,
        payloads: List[str],
        http_client: Any,
        timeout: int,
    ) -> None:
        for payload in payloads:
            self._test_payload_on_param(
                point, param_name, payload, http_client, timeout
            )

    def _scan_input_point(
        self, point: InputPoint, max_payloads: int, http_client: Any, timeout: int
    ) -> None:
        for param_name in list(point.parameters.keys()):
            # 토큰 파라미터 스킵
            if self._should_skip_param(param_name):
                continue

            # 페이로드 제한 적용
            payloads = self.payloads
            if max_payloads:
                payloads = payloads[:max_payloads]

            # 파라미터 스캔
            self._scan_parameter(point, param_name, payloads, http_client, timeout)

    def _scan_single_url(
        self, url: str, http_client: Any, max_payloads: int, timeout: int
    ) -> None:
        self._urls_scanned += 1

        # 입력 포인트 탐지
        points = self._detect_input_points(url, http_client)

        # 토큰 갱신
        self._refresh_input_point_tokens(points, http_client)

        # 각 입력 포인트 스캔
        for point in points:
            self._scan_input_point(point, max_payloads, http_client, timeout)

    def run(self, context: PluginContext) -> PluginResult:
        start_dt = datetime.now(timezone.utc)
        self._reset_state()

        # 설정 추출
        config = self._extract_config(context)
        http_client = config["http_client"]
        max_payloads = config["max_payloads"]
        timeout = config["timeout"]
        target_urls = self._extract_target_urls(context)

        # 스캔 실행
        status = PluginStatus.SUCCESS
        plugin_error = None

        if not target_urls:
            status = PluginStatus.SKIPPED
        else:
            try:
                for url in target_urls:
                    self._scan_single_url(url, http_client, max_payloads, timeout)
            except Exception as exc:  # noqa: BLE001
                status = PluginStatus.FAILED
                plugin_error = PluginError(
                    error_type=type(exc).__name__,
                    message=str(exc),
                    traceback=None,
                    context={"target_urls": target_urls},
                )
                logger.exception("XSS 스캐너 에러: %s", exc)

        # 결과 생성
        return self._build_result(context, start_dt, status, plugin_error)

    def _build_result(
        self,
        context: PluginContext,
        start_dt: datetime,
        status: PluginStatus,
        plugin_error,
    ) -> PluginResult:
        end_dt = datetime.now(timezone.utc)
        s2n_findings = self._as_s2n_findings()

        # 메타데이터 구성
        metadata = {"payloads_tried": len(self.payloads)}
        if status == PluginStatus.SUCCESS and not s2n_findings:
            metadata["note"] = "XSS 취약점이 발견되지 않음"

        return PluginResult(
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

        # Stored XSS 테스트

    def _test_stored(self, point: InputPoint) -> Optional[PayloadResult]:
        params = point.parameters.copy()
        unique_tag = (
            f"s2n_stored_{int(time.time())}"  # 고유 태그 생성 (타임스탬프 기반)
        )
        payload = f"<script>alert('{unique_tag}')</script>"  # Stored XSS 페이로드

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
            # Stored XSS 페이로드 전송 (POST/GET)
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

        # Stored XSS가 반영되기까지 대기
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
        """Reflected XSS 테스트"""
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
        # 페이로드 컨텍스트 탐지 (html/attribute/mixed)
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
        # Reflected XSS 취약점 결과 기록
        key = f"{point.url}|{param_name}|{point.method}"
        finding = self.findings.get(key)
        if not finding:
            finding = Finding(url=point.url, parameter=param_name, method=point.method)
            self.findings[key] = finding
        finding.matches.append(result)

    def _record_stored(self, point: InputPoint, result: PayloadResult) -> None:
        # Stored XSS 취약점 결과 기록
        key = f"{point.url}|[stored]|{point.method}"
        finding = self.findings.get(key)
        if not finding:
            finding = Finding(url=point.url, parameter="[stored]", method=point.method)
            self.findings[key] = finding
        finding.matches.append(result)

    def _as_s2n_findings(self) -> List[S2NFinding]:
        # 내부 Finding을 S2NFinding 리스트로 변환
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
