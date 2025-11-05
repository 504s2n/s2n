"""
s2n-xss: XSS Vulnerability Scanner
Developer-friendly XSS detection optimized for Korean web applications

Features:
- ✨ Cross-Site Scripting (XSS) detection
- ✨ Interactive scanning mode
- ✨ Context-aware payload selection
- ✨ Korean encoding issue detection (UTF-8, EUC-KR, fullwidth chars)
- ✨ Developer-friendly detailed reports with fix recommendations
- ✨ Lightweight and CI/CD friendly
- ✨ Automatic input point detection (no need to specify parameters manually)
- ✨ HTML form auto-parsing for DVWA and other web applications
- ✨ POST/GET method auto-detection
"""

import json
import requests
import re
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from typing import Dict, List, Tuple, Optional
from html.parser import HTMLParser
import time

TOKEN_KEYWORDS = ("token", "csrf", "nonce")
XSS_SEVERITY_PROFILES = {
    "Stored XSS": ("HIGH", 8.8),
    "Reflected XSS": ("HIGH", 7.4),
    "DOM XSS": ("MEDIUM", 6.5),
}

class FormParser(HTMLParser):
    """
    자동 입력 지점 탐지를 위해 HTML에서 폼과 입력 필드를 추출하는 파서
    """

    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == "form":
            self.current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
            }

        elif tag in ["input", "textarea", "select"] and self.current_form is not None:
            input_field = {
                "type": attrs_dict.get("type", "text"),
                "name": attrs_dict.get("name", ""),
                "value": attrs_dict.get("value", ""),
                "tag": tag,
            }

            if input_field["name"]:
                self.current_form["inputs"].append(input_field)

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


class InputPointDetector:
    """
    웹 페이지에서 입력 지점을 자동으로 탐지
    URL 파라미터, HTML 폼을 자동으로 찾아냄
    """

    def __init__(self, session: requests.Session):
        self.session = session

    def detect_input_points(self, url: str) -> List[Dict]:
        """
        URL에서 모든 입력 지점을 탐지

        Returns:
            [{url, method, params, source}, ...]
        """
        input_points = []

        # 1. URL 파라미터 추출
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        if url_params:
            params = {
                k: v[0] if isinstance(v, list) else v for k, v in url_params.items()
            }
            input_points.append(
                {
                    "url": url.split("?")[0],
                    "method": "GET",
                    "params": params,
                    "source": "url",
                }
            )

        # 2. HTML 폼 파싱
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                parser = FormParser()
                parser.feed(response.text)

                for form in parser.forms:
                    if form["inputs"]:
                        action_url = (
                            urljoin(url, form["action"]) if form["action"] else url
                        )

                        params = {}
                        for inp in form["inputs"]:
                            # submit 버튼은 제외
                            input_type = inp["type"].lower()
                            name = inp["name"]
                            if not name:
                                continue

                            if input_type in ["submit", "button"]:
                                params[name] = inp["value"] if inp["value"] else name
                                continue

                            params[name] = inp["value"] if inp["value"] else "test"

                            # ✨ Preserve hidden inputs like user_token
                            if input_type == "hidden":
                                params[name] = inp["value"]

                        if params:
                            input_points.append(
                                {
                                    "url": action_url,
                                    "method": form["method"],
                                    "params": params,
                                    "source": "form",
                                }
                            )
        except Exception as e:
            print(f"  [!] Error detecting forms: {e}")

        return input_points


class DOMXSSDetector:
    """
    DOM 기반 XSS를 탐지하기 위한 간단한 정적 분석기
    """

    DANGEROUS_SOURCES = [
        r"location\.hash",
        r"location\.search",
        r"location\.href",
        r"document\.URL",
        r"document\.documentURI",
        r"document\.referrer",
        r"window\.name",
    ]

    DANGEROUS_SINKS = [
        r"document\.write\s*\(",
        r"document\.writeln\s*\(",
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"eval\s*\(",
        r"setTimeout\s*\(",
        r"setInterval\s*\(",
        r"Function\s*\(",
    ]

    def detect_dom_xss(self, html: str) -> List[Tuple[str, str]]:
        """
        HTML 문서에서 위험한 소스/싱크 조합을 찾아 DOM XSS 가능성을 반환
        """
        findings: List[Tuple[str, str]] = []
        script_pattern = r"<script[^>]*>(.*?)</script>"
        scripts = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)

        for script in scripts:
            sources = [
                pattern
                for pattern in self.DANGEROUS_SOURCES
                if re.search(pattern, script)
            ]
            sinks = [
                pattern for pattern in self.DANGEROUS_SINKS if re.search(pattern, script)
            ]
            for source in sources:
                for sink in sinks:
                    findings.append((source, sink))

        return findings


class StoredXSSDetector:
    """
    저장형 XSS 탐지를 위한 도우미
    """

    EXCLUDED_FIELDS = {"submit", "btnsign"}

    def __init__(self, session: requests.Session):
        self.session = session

    @staticmethod
    def _update_tokens_from_html(html: str, data: Dict[str, str]) -> None:
        parser = FormParser()
        parser.feed(html)
        for form in parser.forms:
            for inp in form["inputs"]:
                name = inp["name"]
                if not name:
                    continue
                lower = name.lower()
                if any(keyword in lower for keyword in TOKEN_KEYWORDS):
                    data[name] = inp.get("value", "")

    def test_stored_xss(
        self, url: str, form_data: Dict[str, str], method: str
    ) -> Tuple[bool, str]:
        unique_id = f"s2n_stored_{int(time.time())}"
        payload = f"<script>alert('{unique_id}')</script>"

        test_data = form_data.copy() if form_data else {}

        try:
            response = self.session.get(url, timeout=10)
            response.encoding = response.apparent_encoding
            self._update_tokens_from_html(response.text, test_data)
        except Exception:
            pass

        for key in list(test_data.keys()):
            lower = key.lower()
            if lower in self.EXCLUDED_FIELDS or any(
                keyword in lower for keyword in TOKEN_KEYWORDS
            ):
                continue
            test_data[key] = payload

        try:
            if method.upper() == "POST":
                send_resp = self.session.post(url, data=test_data, timeout=10)
                send_resp.encoding = send_resp.apparent_encoding
            else:
                send_resp = self.session.get(url, params=test_data, timeout=10)
                send_resp.encoding = send_resp.apparent_encoding

            self._update_tokens_from_html(send_resp.text, test_data)

            time.sleep(0.8)
            verify_resp = self.session.get(url, timeout=10)
            verify_resp.encoding = verify_resp.apparent_encoding
            body = verify_resp.text

            if payload in body or unique_id in body:
                return True, payload

            import html

            if html.escape(payload) in body:
                return True, payload

            return False, payload
        except Exception:
            return False, payload

# ============================================================
# ✨ Payload Categorizer (페이로드 분류기)
# ============================================================
class PayloadCategorizer:
    """
    페이로드를 카테고리별로 분류하여 더 나은 리포트 생성
    """

    @staticmethod
    def categorize_payload(payload: str) -> Dict[str, str]:
        """
        페이로드를 카테고리로 분류

        Returns:
            {
                'category': 'basic_script' | 'event_handler' | 'encoding' | ...,
                'category_ko': '기본 스크립트' | '이벤트 핸들러' | ...,
                'description': '설명'
            }
        """
        payload_lower = payload.lower()

        # 1. 기본 스크립트 태그
        if (
            "<script>" in payload_lower
            and "fromcharcode" not in payload_lower
            and "atob" not in payload_lower
        ):
            return {
                "category": "basic_script",
                "category_ko": "기본 스크립트 태그",
                "description": "Standard <script> tag injection",
            }

        # 2. 이벤트 핸들러
        if any(
            event in payload_lower
            for event in [
                "onerror",
                "onload",
                "onfocus",
                "onclick",
                "onmouseover",
                "ontoggle",
            ]
        ):
            return {
                "category": "event_handler",
                "category_ko": "이벤트 핸들러",
                "description": "HTML event handler exploitation",
            }

        # 3. 인코딩 우회
        if any(enc in payload for enc in ["%", "\\u", "\\x", "&#", "&lt;", "&gt;"]):
            return {
                "category": "encoding_bypass",
                "category_ko": "인코딩 우회",
                "description": "Encoded payload to bypass filters",
            }

        # 4. 난독화
        if (
            "fromcharcode" in payload_lower
            or "atob" in payload_lower
            or "eval" in payload_lower
        ):
            return {
                "category": "obfuscation",
                "category_ko": "난독화",
                "description": "Obfuscated JavaScript code",
            }

        # 5. 공백 우회
        if any(char in payload for char in ["/", "\t", "\n"]) and "<" in payload:
            return {
                "category": "whitespace_bypass",
                "category_ko": "공백 문자 우회",
                "description": "Alternative whitespace characters",
            }

        # 6. 한글/인코딩 특화
        if any(
            pattern in payload
            for pattern in ["EUC-KR", "테스트", "한글", "가나다", "%C5%", "%D7%"]
        ):
            return {
                "category": "korean_encoding",
                "category_ko": "한글 인코딩",
                "description": "Korean encoding specific payload",
            }

        # 7. 대소문자 혼합
        if "<script>" not in payload_lower and "<script" in payload_lower:
            return {
                "category": "case_variation",
                "category_ko": "대소문자 변형",
                "description": "Mixed case to bypass filters",
            }

        # 8. HTML 주석 우회
        if "<!--" in payload or "//-->" in payload:
            return {
                "category": "comment_bypass",
                "category_ko": "HTML 주석 우회",
                "description": "HTML comment manipulation",
            }

        # 기타
        return {
            "category": "other",
            "category_ko": "기타",
            "description": "Other XSS technique",
        }


# ============================================================
# S2NXSSPlugin 클래스 (개선된 버전)
# ============================================================


class S2NXSSPlugin:
    """
    s2n-xss 코어 엔진

    ✨ IMPROVED v2.1:
    - 동일 위치 취약점 그룹핑
    - 페이로드 카테고리 분류
    - 향상된 리포트 구조
    """

    def __init__(
        self,
        payloads_path: str,
        cookies: Optional[Dict] = None,
        timeout: int = 10,
        auto_detect: bool = True,
    ):
        """
        Args:
            payloads_path: 페이로드 JSON 파일 경로
            cookies: 세션 쿠키 (선택)
            timeout: 요청 타임아웃 (초)
            auto_detect: 자동 입력 지점 탐지 활성화
        """
        self.timeout = timeout
        self.auto_detect = auto_detect

        # ✨ IMPROVED: 결과 저장 구조 변경 (기존: 단순 리스트 -> 새로운: 그룹핑된 딕셔너리)
        self.results = []  # 기존 호환성을 위해 유지
        self.grouped_vulnerabilities = {}  # ✨ 위치별로 그룹핑된 취약점
        self.total_payload_tests = 0

        self.session = requests.Session()

        if cookies:
            # Apply cookies (e.g., PHPSESSID, security level)
            self.session.cookies.update(cookies)

        # 사용자 에이전트 설정
        self.session.headers.update({"User-Agent": "s2n-xss/2.1 (Security Scanner)"})

        # 페이로드 로드
        with open(payloads_path, "r", encoding="utf-8") as f:
            self.payloads_data = json.load(f)

        # 탐지기 초기화
        self.input_detector = InputPointDetector(self.session)
        self.dom_detector = DOMXSSDetector()
        self.stored_detector = StoredXSSDetector(self.session)

        print(
            f"[+] Loaded {self.payloads_data['metadata']['total_payloads']} payloads from {payloads_path}"
        )

    def _update_tokens_from_html(self, html: str, params: Dict[str, str]) -> None:
        """
        폼 HTML에서 token/csrf/nonce 필드 값을 추출하여 params를 최신 상태로 유지
        """
        parser = FormParser()
        parser.feed(html)
        for form in parser.forms:
            for inp in form["inputs"]:
                name = inp["name"]
                if not name:
                    continue
                lower = name.lower()
                if any(keyword in lower for keyword in TOKEN_KEYWORDS):
                    params[name] = inp.get("value", "")

    def _record_dom_vulnerabilities(self, url: str, dom_vulns: List[Tuple[str, str]]):
        """
        DOM 기반 취약점 결과를 그룹 구조에 반영
        """
        if not dom_vulns:
            return

        dom_key = f"{url}|dom_source|GET"
        dom_group = self.grouped_vulnerabilities.get(dom_key)
        if not dom_group:
            dom_group = {
                "location": {
                    "url": url,
                    "parameter": "dom_source",
                    "method": "GET",
                },
                "successful_payloads": [],
                "first_detected": time.strftime("%Y-%m-%d %H:%M:%S"),
                "xss_type": "DOM XSS",
            }
            self.grouped_vulnerabilities[dom_key] = dom_group

        existing = {entry["payload"] for entry in dom_group["successful_payloads"]}

        for source, sink in dom_vulns:
            payload_repr = f"{source} -> {sink}"
            if payload_repr in existing:
                continue
            dom_group["successful_payloads"].append(
                {
                    "payload": payload_repr,
                    "context": "dom",
                    "category": "dom_analysis",
                    "category_ko": "DOM 분석",
                    "description": f"Source: {source}, Sink: {sink}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
            existing.add(payload_repr)

    def _detect_dom_vulnerabilities(self, url: str) -> None:
        """
        지정한 URL에서 DOM XSS 패턴을 탐지하여 결과에 반영
        """
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.encoding = response.apparent_encoding
            dom_vulns = self.dom_detector.detect_dom_xss(response.text)
            if dom_vulns:
                print(
                    f"[!] DOM XSS indicator detected at {url} "
                    f"({len(dom_vulns)} source/sink pair{'s' if len(dom_vulns) > 1 else ''})"
                )
                self._record_dom_vulnerabilities(url, dom_vulns)
        except Exception:
            pass

    def _promote_to_stored(
        self, url: str, method: str, stored_payload: str, context: str = "stored"
    ) -> None:
        """
        동일 URL/메서드의 취약점을 저장형으로 재분류
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        for vuln in self.grouped_vulnerabilities.values():
            loc = vuln["location"]
            if loc.get("url") == url and loc.get("method") == method:
                vuln["xss_type"] = "Stored XSS"
                for payload_entry in vuln["successful_payloads"]:
                    payload_entry["context"] = context
                    payload_entry.setdefault("timestamp", timestamp)

        location_key = f"{url}|multiple_fields|{method}"
        stored_group = self.grouped_vulnerabilities.get(location_key)

        if not stored_group:
            stored_group = {
                "location": {
                    "url": url,
                    "parameter": "multiple_fields",
                    "method": method,
                },
                "successful_payloads": [],
                "first_detected": timestamp,
                "xss_type": "Stored XSS",
            }
            self.grouped_vulnerabilities[location_key] = stored_group

        stored_group["xss_type"] = "Stored XSS"
        stored_group["location"]["parameter"] = "multiple_fields"
        existing_payloads = {
            entry["payload"] for entry in stored_group["successful_payloads"]
        }
        if stored_payload not in existing_payloads:
            stored_group["successful_payloads"].append(
                {
                    "payload": stored_payload,
                    "context": context,
                    "category": "stored_injection",
                    "category_ko": "저장형 주입",
                    "description": "Payload persisted across requests",
                    "timestamp": timestamp,
                }
            )

    def select_payloads(self) -> List[str]:
        """
        모든 페이로드 선택 (기본 강도: Aggressive / intensity=3)

        Returns:
            전체 페이로드 리스트
        """
        payloads = []

        # 기본 페이로드
        payloads.extend(self.payloads_data["payloads"]["html_context"]["basic"])

        # 중급 페이로드
        payloads.extend(
            self.payloads_data["payloads"]["html_context"]["korean_specific"]
        )
        payloads.extend(
            self.payloads_data["payloads"]["attribute_context"]["double_quote"]
        )
        payloads.extend(self.payloads_data["filter_bypass"]["obfuscation"])
        payloads.extend(self.payloads_data["filter_bypass"]["space_bypass"])
        payloads.extend(self.payloads_data["filter_bypass"]["comment_bypass"])
        payloads.extend(self.payloads_data["korean_encoding_specific"]["euc_kr_bypass"])

        # 고급 페이로드
        payloads.extend(self.payloads_data["filter_bypass"]["encoding"])
        payloads.extend(
            self.payloads_data["payloads"]["attribute_context"]["single_quote"]
        )
        payloads.extend(self.payloads_data["payloads"]["attribute_context"]["no_quote"])
        payloads.extend(
            self.payloads_data["korean_encoding_specific"]["fullwidth_chars"]
        )

        return payloads

    def test_payload(
        self, url: str, params: Dict, payload: str, method: str = "GET"
    ) -> Tuple[bool, str]:
        """
        단일 페이로드 테스트

        Returns:
            (is_vulnerable, detected_context)
        """
        test_params = params.copy()

        try:
            if method.upper() == "POST":
                response = self.session.post(
                    url, data=test_params, timeout=self.timeout
                )
                # Ensure correct encoding detection
                response.encoding = response.apparent_encoding
            else:
                response = self.session.get(
                    url, params=test_params, timeout=self.timeout
                )
                # Ensure correct encoding detection
                response.encoding = response.apparent_encoding

            # 응답에서 페이로드 확인
            import html

            escaped = html.escape(payload)
            # Combine redirect chain and final page for more accurate detection
            final_html = response.text
            if response.history:
                for hist in response.history:
                    hist.encoding = hist.apparent_encoding
                    final_html += hist.text

            # POST 실행 후 토큰이 갱신되는 경우를 대비해 params 업데이트
            self._update_tokens_from_html(final_html, params)

            if payload in final_html or escaped in final_html:
                # 컨텍스트 감지
                context = self.detect_context(final_html, payload)
                return True, context

            return False, ""

        except Exception as e:
            return False, ""

    def detect_context(self, html: str, payload: str) -> str:
        """
        페이로드가 삽입된 컨텍스트 감지

        Returns:
            'html', 'attribute', 'javascript', 'korean_euc_kr' 등
        """
        # 한글 인코딩 체크
        if any(
            korean in payload
            for korean in ["한글", "테스트", "EUC-KR", "가나다", "%C5%", "%D7%"]
        ):
            return "korean_euc_kr"

        # 속성 컨텍스트
        if re.search(rf'<\w+[^>]*\s+\w+\s*=\s*["\']?[^"\']*{re.escape(payload)}', html):
            return "attribute"

        # JavaScript 컨텍스트
        if re.search(
            rf"<script[^>]*>.*{re.escape(payload)}.*</script>", html, re.DOTALL
        ):
            return "javascript"

        # HTML 컨텍스트
        return "html"

    def scan(
        self,
        target_url: str,
        params: Optional[Dict] = None,
        method: str = "GET",
    ) -> List[Dict]:
        """
        XSS 스캔 실행 (기본 강도: Aggressive / intensity=3)

        Args:
            target_url: 대상 URL
            params: 파라미터 (자동 탐지 시 None)
            method: HTTP 메소드

        Returns:
            취약점 리스트
        """
        print(f"\n[*] Target: {target_url}")
        print(f"[*] Mode: {'AUTO' if self.auto_detect else 'MANUAL'}")
        print(f"[*] Intensity: 3/3 (Aggressive - All payloads)")

        # 카운터 초기화
        self.total_payload_tests = 0

        # 입력 지점 탐지
        if self.auto_detect:
            print("\n[*] Detecting input points...")
            input_points = self.input_detector.detect_input_points(target_url)
            print(f"[+] Found {len(input_points)} input point(s)")
        else:
            if not params:
                parsed = urlparse(target_url)
                params = dict(parse_qs(parsed.query))
                params = {
                    k: v[0] if isinstance(v, list) else v for k, v in params.items()
                }
                target_url = target_url.split("?")[0]

            input_points = [
                {
                    "url": target_url,
                    "method": method,
                    "params": params,
                    "source": "manual",
                }
            ]

        if not input_points:
            print("[!] No input points found. Attempting DOM XSS analysis...")
            self._detect_dom_vulnerabilities(target_url)
            return self._rebuild_results()

        # 페이로드 선택 (모든 페이로드 사용)
        payloads = self.select_payloads()
        print(f"[*] Testing {len(payloads)} payload(s)...\n")

        # 각 입력 지점 테스트
        for idx, point in enumerate(input_points, 1):
            url = point["url"]
            method = point["method"]
            params = point["params"]
            source = point["source"]

            print(f"[{idx}/{len(input_points)}] Testing: {url}")
            print(f"    Method: {method}")
            print(f"    Parameters: {list(params.keys())}")
            print(f"    Source: {source}")

            # Unified XSS test (Reflected-like only)
            for param_name in list(params.keys()):
                lower_param = param_name.lower()
                if lower_param in ["submit", "btnsign"] or any(
                    keyword in lower_param for keyword in TOKEN_KEYWORDS
                ):
                    continue

                print(f"\n  [*] Testing parameter: {param_name}")

                # Unified location key
                location_key = f"{url}|{param_name}|{method}"

                if location_key not in self.grouped_vulnerabilities:
                    self.grouped_vulnerabilities[location_key] = {
                        "location": {
                            "url": url,
                            "parameter": param_name,
                            "method": method,
                        },
                        "successful_payloads": [],
                        "first_detected": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "xss_type": "Reflected XSS",
                    }

                successful_count = 0
                for payload in payloads:
                    self.total_payload_tests += 1
                    test_params = dict(params)
                    test_params[param_name] = payload

                    is_vulnerable, context = self.test_payload(
                        url, test_params, payload, method
                    )

                    if is_vulnerable:
                        successful_count += 1
                        category_info = PayloadCategorizer.categorize_payload(payload)
                        payload_info = {
                            "payload": payload,
                            "context": context,
                            "category": category_info["category"],
                            "category_ko": category_info["category_ko"],
                            "description": category_info["description"],
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        }
                        self.grouped_vulnerabilities[location_key][
                            "successful_payloads"
                        ].append(payload_info)

                print(f"  [+] {successful_count}/{len(payloads)} payloads successful")
                if successful_count == 0:
                    self.grouped_vulnerabilities.pop(location_key, None)
                    continue

            if method.upper() == "POST" and source == "form":
                stored_found, stored_payload = self.stored_detector.test_stored_xss(
                    url, params, method
                )
                if stored_found:
                    print("  [!] Stored payload persisted after submission")
                    self._promote_to_stored(url, method, stored_payload)

            # 추가 DOM XSS 점검 (파라미터 기반 테스트 이후)
            self._detect_dom_vulnerabilities(url)

        return self._rebuild_results()

    def _rebuild_results(self) -> List[Dict]:
        """
        그룹핑된 취약점 정보를 기반으로 고유한 결과 리스트를 생성
        """
        rebuilt_results = []

        for vuln in self.grouped_vulnerabilities.values():
            location = vuln["location"]
            method = location.get("method", "GET")
            url = location.get("url", "")
            parameter = location.get("parameter", "")
            xss_type = vuln.get("xss_type", "Reflected XSS")
            severity, cvss = XSS_SEVERITY_PROFILES.get(xss_type, ("HIGH", 7.5))

            payload_example = ""
            context_detected = ""
            if vuln["successful_payloads"]:
                payload_example = vuln["successful_payloads"][0].get("payload", "")
                context_detected = vuln["successful_payloads"][0].get("context", "")

            injection_point = f"{method} {url}"
            if parameter and parameter not in ["dom_source"]:
                if method.upper() == "GET":
                    injection_point += (
                        f"?{parameter}={payload_example}"
                        if payload_example
                        else f"?{parameter}=<payload>"
                    )
                else:
                    injection_point += f" ({parameter})"
            elif parameter == "dom_source" or xss_type == "DOM XSS":
                injection_point += " (DOM context)"

            human_parameter = parameter or "N/A"
            human_parameter_ko = parameter or "N/A"
            if parameter == "dom_source" or xss_type == "DOM XSS":
                human_parameter = "DOM context"
                human_parameter_ko = "DOM 컨텍스트"

            rebuilt_results.append(
                {
                    "scanner": "s2n-xss",
                    "vulnerability_type": "Cross-Site Scripting (XSS)",
                    "vulnerability_type_ko": "크로스 사이트 스크립팅 (XSS)",
                    "severity": severity,
                    "cvss_score": cvss,
                    "location": location,
                    "xss_type": xss_type,
                    "evidence": {
                        "payload_used": payload_example,
                        "context_detected": context_detected,
                        "injection_point": injection_point,
                    },
                    "description": {
                        "korean": f"'{human_parameter_ko}' 위치에서 {xss_type} 취약점이 확인되었습니다.",
                        "english": f"{xss_type} detected at {human_parameter}.",
                    },
                    "impact": {
                        "korean": [
                            "사용자 세션 쿠키 탈취",
                            "사용자 계정 권한으로 악의적 행위 수행",
                            "피싱 페이지로 리다이렉트",
                            "사용자 입력 정보 탈취",
                        ],
                        "english": [
                            "Session cookie theft",
                            "Unauthorized actions with user privileges",
                            "Redirection to phishing pages",
                            "User input data exfiltration",
                        ],
                    },
                    "fix_recommendation": {
                        "korean": "모든 사용자 입력값을 검증하고, 출력 시 HTML 이스케이프 처리를 적용하세요.",
                        "english": "Validate all user inputs and apply HTML escaping on output.",
                    },
                    "references": [
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://portswigger.net/web-security/cross-site-scripting",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ],
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
            )

        self.results = rebuilt_results
        return rebuilt_results

# ============================================================
# Interactive launcher (범용 버전)
# ============================================================
if __name__ == "__main__":
    import os
    import sys

    print("\n" + "=" * 70)
    print("s2n-xss : XSS Vulnerability Scanner")
    print("=" * 70)
    print("\n✨ Features:")
    print("  ✓ Cross-Site Scripting (XSS) detection")
    print("  ✓ Context-aware payload selection")
    print("  ✓ Korean encoding detection (EUC-KR, fullwidth)")
    print("  ✓ Developer-friendly reports (KR/EN)")
    print("  ✓ Interactive mode")
    print("  ✓ Auto input detection")
    print()

    # 페이로드 파일 경로
    default_payload = "xss_payloads.json"
    if not os.path.exists(default_payload):
        default_payload = os.path.join(os.path.dirname(__file__), "xss_payloads.json")

    # 1. Target URL 입력
    print("=" * 70)
    print("Step 1: Target URL")
    print("=" * 70)
    try:
        target_url = input("\n[>] Enter target URL: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n\nAborted by user.")
        sys.exit(0)

    if not target_url:
        print("\n[!] No URL provided. Exiting.")
        sys.exit(0)

    # URL 파싱하여 파라미터 확인
    parsed = urlparse(target_url)
    has_params = bool(parsed.query)

    # 2. 인증 쿠키 입력 (필수)
    print("\n" + "=" * 70)
    print("Step 2: Authentication")
    print("=" * 70)

    is_dvwa = "dvwa" in target_url.lower()

    if is_dvwa:
        print("\n[*] DVWA detected!")
        print("\nTo get cookies:")
        print("  1. Login to DVWA (admin/password)")
        print("  2. F12 → Application → Cookies")
        print("  3. Copy PHPSESSID value")

    phpsessid = input("\n[*] Enter PHPSESSID for authentication: ").strip()

    cookies = None
    if phpsessid:
        cookies = {"PHPSESSID": phpsessid}

        if is_dvwa:
            security = (
                input("[>] Security level (low/medium/high, default=low): ")
                .strip()
                .lower()
            )
            cookies["security"] = (
                security if security in ["low", "medium", "high"] else "low"
            )

        print(f"\n[+] Cookies configured: {list(cookies.keys())}")
    else:
        print(
            "[!] Warning: No PHPSESSID provided. Some targets may require authentication."
        )

    # 자동 스캔 모드 활성화 (필수)
    auto_detect = True
    print(f"[+] Scan Mode: AUTO (automatic input point detection enabled)")

    if not has_params:
        print("[*] No parameters in URL - will auto-detect forms and parameters")

    # 3. 스캐너 초기화
    print("\n" + "=" * 70)
    print("Initializing Scanner")
    print("=" * 70)

    if not os.path.exists(default_payload):
        print(f"\n[ERROR] Payload file not found: {default_payload}")
        print("\nPlease ensure xss_payloads.json is in the same directory")
        sys.exit(1)

    try:
        scanner = S2NXSSPlugin(
            payloads_path=default_payload,
            cookies=cookies,
            timeout=10,
            auto_detect=auto_detect,
        )
    except Exception as e:
        print(f"\n[ERROR] Failed to initialize: {e}")
        sys.exit(1)

    # 4. 스캔 실행
    print("\n" + "=" * 70)
    print("Starting Scan")
    print("=" * 70)

    try:
        start_time = time.time()
        results = scanner.scan(target_url=target_url, params=None, method="GET")
        elapsed = time.time() - start_time
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Scan failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    # 6. 결과 출력
    print("\n" + "=" * 70)
    print("SCAN RESULTS")
    print("=" * 70)
    print(f"\nScan completed in {elapsed:.1f} seconds")
    print(f"Target: {target_url}")

    if not results:
        print("\n✅ No XSS vulnerabilities detected")
        print("\nPossible reasons:")
        print("  - Target is properly secured")
        print("  - No input points found (check authentication)")
        print("  - Filters are blocking payloads")
    else:
        unique_locations = len(scanner.grouped_vulnerabilities)
        print(
            f"\nSummary: {len(results)} finding(s) across {unique_locations} vulnerable location(s)"
        )

        # 심각도별 분류
        severity_count = {}
        for vuln in results:
            sev = vuln["severity"]
            severity_count[sev] = severity_count.get(sev, 0) + 1

        if severity_count:
            print("\nSeverity distribution:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = severity_count.get(sev, 0)
                if count > 0:
                    print(f"  {sev}: {count}")

        result_lookup = {}
        for res in results:
            loc = res.get("location", {})
            key = f"{loc.get('url')}|{loc.get('parameter')}|{loc.get('method')}"
            result_lookup[key] = res

        print("\n" + "-" * 70)
        print("Detected Vulnerabilities:")
        print("-" * 70)

        for i, (location_key, vuln_data) in enumerate(
            scanner.grouped_vulnerabilities.items(), 1
        ):
            print(f"\n[{i}] {vuln_data['location']['url']}")
            print(f"    Parameter: {vuln_data['location']['parameter']}")
            print(f"    Method: {vuln_data['location']['method']}")
            print(f"    Successful payloads: {len(vuln_data['successful_payloads'])}")

            res_meta = result_lookup.get(location_key, {})
            severity = res_meta.get("severity", "UNKNOWN")
            cvss = res_meta.get("cvss_score", "N/A")
            vuln_type = res_meta.get("xss_type", "Unknown")
            print(f"    Severity: {severity} (CVSS {cvss})")
            print(f"    Type: {vuln_type}")

            # 카테고리별 분류
            categories = {}
            for p in vuln_data["successful_payloads"]:
                cat = p["category_ko"]
                categories[cat] = categories.get(cat, 0) + 1

            categories_line = (
                ", ".join(f"{k}({v})" for k, v in categories.items()) if categories else "-"
            )
            print(f"    Categories: {categories_line}")

    print("\n" + "=" * 70)
    print("Scan Complete")
    print("=" * 70)
    print()

    sys.exit(0 if not results else len(results))
