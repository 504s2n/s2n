from __future__ import annotations

import html
import json
import time
import re
import logging
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

import requests

# 전용 로거 (CLI에서 핸들러/레벨을 설정)
logger = logging.getLogger("s2n_xss")

# CSRF 토큰, nonce 등을 탐지하기 위한 키워드 목록
TOKEN_KEYWORDS = ("token", "csrf", "nonce")
# 요청 타임아웃 설정 (초)
DEFAULT_TIMEOUT = 10
# User-Agent 헤더 값 설정
USER_AGENT = "s2n_xss/2.3 (Reflected Scanner)"
# 토큰 패턴 정규식 템플릿, HTML input 태그에서 특정 키워드가 포함된 name 속성과 value 값을 추출
TOKEN_PATTERN_TEMPLATE = (
    r'name=["\']([^"\']*{keyword}[^"\']*)["\']\s+value=["\']([^"\']+)["\']'
)


@dataclass
class PayloadResult:
    # 페이로드 테스트 결과를 저장하는 데이터 클래스
    payload: str  # 테스트한 페이로드 문자열
    context: str  # 페이로드가 반영된 컨텍스트 (html, attribute 등)
    category: str  # 취약점 유형 (reflected, stored)
    category_ko: str  # 한글로 된 취약점 유형명
    description: str  # 상세 설명


@dataclass
class Finding:
    # 취약점 발견 정보를 저장하는 데이터 클래스
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


@dataclass
class InputPoint:
    # 입력 가능한 지점(URL 파라미터, 폼 입력 필드) 정보를 저장하는 데이터 클래스
    url: str  # 입력 지점 URL
    method: str  # HTTP 메서드
    parameters: Dict[str, str]  # 파라미터 이름과 기본값 딕셔너리
    source: str  # 입력 지점 출처 (url, form, manual)


class FormParser(HTMLParser):
    """Extract forms and their input fields."""

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
    """Locate URL parameters and HTML form inputs."""

    # URL 쿼리 파라미터 및 HTML 폼 입력 필드를 탐지하여 입력 지점 리스트를 반환하는 클래스

    def __init__(self, session: requests.Session):
        self.session = session  # requests 세션 객체

    def detect(self, url: str) -> List[InputPoint]:
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
            response = self.session.get(url, timeout=DEFAULT_TIMEOUT)
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
    # HTML 내용에서 CSRF 토큰 등 보안 토큰을 찾아 파라미터 딕셔너리에 업데이트
    for keyword in TOKEN_KEYWORDS:
        pattern = re.compile(TOKEN_PATTERN_TEMPLATE.format(keyword=keyword))
        for match in pattern.finditer(html_content):
            field_name, value = match.groups()
            params[field_name] = value


def refresh_tokens(
    session: requests.Session, url: str, params: Dict[str, str], method: str
) -> None:
    # 요청을 보내고 응답에서 토큰 정보를 갱신하는 함수
    try:
        if method.upper() == "GET":
            response = session.get(url, params=params, timeout=DEFAULT_TIMEOUT)
        else:
            response = session.get(url, timeout=DEFAULT_TIMEOUT)
        response.encoding = response.apparent_encoding
        update_tokens_from_html(response.text, params)
    except Exception as exc:
        logger.warning("Failed to refresh tokens for %s (%s): %s", url, method, exc)


def extract_payloads(payloads_json: Dict) -> List[str]:
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
    # 반사형 및 저장형 XSS 취약점 탐지기 클래스

    def __init__(self, payloads_path: Path, cookies: Optional[Dict[str, str]] = None):
        # 초기화: 페이로드 로드, 세션 설정, 입력 지점 탐지기 생성
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        if cookies:
            self.session.cookies.update(cookies)

        # 페이로드 JSON 파일 로드
        with payloads_path.open("r", encoding="utf-8") as fp:
            payloads_json = json.load(fp)

        # 페이로드 리스트 추출
        self.payloads: List[str] = extract_payloads(payloads_json)
        self.detector = InputPointDetector(self.session)
        self.findings: Dict[str, Finding] = {}

    def _test_stored(self, point: InputPoint) -> Optional[PayloadResult]:
        # 저장형 XSS 테스트 함수
        params = point.parameters.copy()
        unique_tag = (
            f"s2n_stored_{int(time.time())}"  # 고유 태그 생성 (타임스탬프 기반)
        )
        payload = f"<script>alert('{unique_tag}')</script>"  # 저장형 페이로드

        # 토큰 갱신
        refresh_tokens(self.session, point.url, params, point.method)

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
                response = self.session.post(
                    point.url, data=params, timeout=DEFAULT_TIMEOUT
                )
            else:
                response = self.session.get(
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
            verify = self.session.get(point.url, timeout=DEFAULT_TIMEOUT)
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
        # 반사형 XSS 테스트 함수
        params = point.parameters.copy()
        params[param_name] = payload  # 테스트할 파라미터에 페이로드 삽입

        # 토큰 갱신
        refresh_tokens(self.session, point.url, params, point.method)

        try:
            # 요청 전송 (POST/GET)
            if point.method.upper() == "POST":
                response = self.session.post(
                    point.url, data=params, timeout=DEFAULT_TIMEOUT
                )
            else:
                response = self.session.get(
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
        # 반사형 취약점 결과를 findings 딕셔너리에 기록
        key = f"{point.url}|{param_name}|{point.method}"
        finding = self.findings.get(key)
        if not finding:
            finding = Finding(url=point.url, parameter=param_name, method=point.method)
            self.findings[key] = finding
        finding.matches.append(result)

    def _record_stored(self, point: InputPoint, result: PayloadResult) -> None:
        # 저장형 취약점 결과를 findings 딕셔너리에 기록
        key = f"{point.url}|[stored]|{point.method}"
        finding = self.findings.get(key)
        if not finding:
            finding = Finding(url=point.url, parameter="[stored]", method=point.method)
            self.findings[key] = finding
        finding.matches.append(result)

    def scan(
        self,
        target_url: str,
        params: Optional[Dict[str, str]] = None,
        method: str = "GET",
    ) -> List[Dict]:
        # 실제 스캔 수행 함수
        points: List[InputPoint]
        logger.info(
            "[SCAN] Starting scan for %s (payloads=%d)",
            target_url,
            len(self.payloads),
        )

        if params is not None:
            # 수동으로 파라미터가 주어진 경우 입력 지점 리스트에 추가
            points = [
                InputPoint(
                    url=target_url.split("?")[0],
                    method=method,
                    parameters=params or {},
                    source="manual",
                )
            ]
        else:
            # 자동으로 URL 및 폼 입력 지점 탐지
            points = self.detector.detect(target_url)

        for idx, point in enumerate(points, 1):
            field_names = list(point.parameters.keys())
            logger.info(
                "[SCAN] Testing input point #%d (method=%s, fields=%d)",
                idx,
                point.method,
                len(field_names),
            )
            for param_name in field_names:
                lower = param_name.lower()
                # 토큰 관련 파라미터는 건너뜀
                if any(keyword in lower for keyword in TOKEN_KEYWORDS):
                    continue

                success_count = 0
                context_counts: Dict[str, int] = {}
                # 각 페이로드를 테스트하여 취약점 여부 확인
                for payload in self.payloads:
                    result = self._test_payload(point, param_name, payload)
                    if result:
                        self._record(point, param_name, result)
                        success_count += 1
                        context_counts[result.context] = (
                            context_counts.get(result.context, 0) + 1
                        )

                if success_count:
                    summary = ", ".join(
                        f"{ctx}:{cnt}" for ctx, cnt in context_counts.items()
                    )
                    logger.info(
                        "[RESULT] Parameter '%s' success -> %s (total=%d)",
                        param_name,
                        summary,
                        success_count,
                    )
                else:
                    logger.debug(
                        "[RESULT] Parameter '%s' -> no successful payloads", param_name
                    )

            # 저장형 XSS 테스트 (POST 메서드 + 폼 입력 지점인 경우)
            if point.method.upper() == "POST" and point.source == "form":
                stored_result = self._test_stored(point)
                if stored_result:
                    self._record_stored(point, stored_result)
                    logger.info("[RESULT] Stored payload persisted for this form input")

        # 발견된 취약점 리스트를 딕셔너리 형태로 반환
        return [finding.as_dict() for finding in self.findings.values()]

    def print_summary(self) -> None:
        # 스캔 결과 요약 출력 함수
        findings = list(self.findings.values())
        if not findings:
            print("\n✅ No reflected XSS detected")
            return

        print(f"\n⚠️  Reflected/Stored XSS detected in {len(findings)} location(s)")
        for idx, finding in enumerate(findings, 1):
            print(f"\n[{idx}] {finding.url}")
            print(f"    Parameter: {finding.parameter}")
            print(f"    Method: {finding.method}")
            print(f"    Successful payloads: {len(finding.matches)}")
