from __future__ import annotations

import sys
import html
import json
import time
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse
from pathlib import Path

import requests

TOKEN_KEYWORDS = ("token", "csrf", "nonce")
DEFAULT_TIMEOUT = 10
USER_AGENT = "s2n-xss/2.3 (Reflected Scanner)"


# ============================================================
# HTML form parser
# ============================================================


class FormParser(HTMLParser):
    """Extract forms and their input fields."""

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


# ============================================================
# Input point detector
# ============================================================


class InputPointDetector:
    """Locate URL parameters and HTML form inputs."""

    def __init__(self, session: requests.Session):
        self.session = session

    def detect(self, url: str) -> List["InputPoint"]:
        points: List[InputPoint] = []

        # URL query string parameters
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        if url_params:
            params = {k: v[0] if isinstance(v, list) else v for k, v in url_params.items()}
            points.append(
                InputPoint(
                    url=parsed._replace(query="").geturl(),
                    method="GET",
                    parameters=params,
                    source="url",
                )
            )

        # HTML forms
        try:
            response = self.session.get(url, timeout=DEFAULT_TIMEOUT)
            if response.status_code == 200:
                parser = FormParser()
                parser.feed(response.text)
                for form in parser.forms:
                    params = {}
                    for field in form["inputs"]:
                        name = field["name"]
                        value = field["value"] or "test"
                        field_type = field["type"].lower()

                        if field_type in {"submit", "button"}:
                            params[name] = field["value"] or name
                            continue

                        if field_type == "hidden":
                            params[name] = field["value"]
                        else:
                            params[name] = value

                    if params:
                        action = form["action"]
                        target = urljoin(url, action) if action else url
                        points.append(
                            InputPoint(
                                url=target,
                                method=form["method"],
                                parameters=params,
                                source="form",
                            )
                        )
        except Exception:
            pass

        return points


# ============================================================
# Data structures
# ============================================================


@dataclass
class InputPoint:
    url: str
    method: str
    parameters: Dict[str, str]
    source: str


@dataclass
class PayloadResult:
    payload: str
    context: str
    category: str
    category_ko: str
    description: str


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
            "successful_payloads": [result.__dict__ for result in self.matches],
        }


# ============================================================
# Main scanner
# ============================================================


class ReflectedScanner:
    def __init__(self, payloads_path: str, cookies: Optional[Dict] = None):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        if cookies:
            self.session.cookies.update(cookies)

        with open(payloads_path, "r", encoding="utf-8") as fp:
            payloads_json = json.load(fp)

        self.payloads: List[str] = self._extract_payloads(payloads_json)
        self.detector = InputPointDetector(self.session)
        self.findings: Dict[str, Finding] = {}

    @staticmethod
    def _extract_payloads(payloads_json: Dict) -> List[str]:
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

        walk(payloads_json.get("payloads", {}))
        walk(payloads_json.get("filter_bypass", {}))
        walk(payloads_json.get("korean_encoding_specific", {}))
        return [payload for payload in collected if payload]

    def _update_tokens(self, html_content: str, params: Dict[str, str]) -> None:
        for keyword in TOKEN_KEYWORDS:
            pattern = re.compile(
                rf'name=[\"\']([^\"\']*{keyword}[^\"\']*)[\"\']\s+value=[\"\']([^\"\']+)[\"\']'
            )
            for match in pattern.finditer(html_content):
                field_name, value = match.groups()
                params[field_name] = value

    def _refresh_tokens(self, url: str, params: Dict[str, str], method: str) -> None:
        try:
            if method.upper() == "GET":
                response = self.session.get(url, params=params, timeout=DEFAULT_TIMEOUT)
            else:
                response = self.session.get(url, timeout=DEFAULT_TIMEOUT)
            response.encoding = response.apparent_encoding
            self._update_tokens(response.text, params)
        except Exception:
            pass

    def _test_payload(self, point: InputPoint, param_name: str, payload: str) -> Optional[PayloadResult]:
        params = point.parameters.copy()
        params[param_name] = payload

        self._refresh_tokens(point.url, params, point.method)

        try:
            if point.method.upper() == "POST":
                response = self.session.post(point.url, data=params, timeout=DEFAULT_TIMEOUT)
            else:
                response = self.session.get(point.url, params=params, timeout=DEFAULT_TIMEOUT)

            response.encoding = response.apparent_encoding
            body = response.text

            if payload not in body:
                return None

            context = self._detect_context(body, payload)
            category = "reflected"
            category_ko = "반사형"
            description = "Payload echoed without encoding"

            return PayloadResult(
                payload=payload,
                context=context,
                category=category,
                category_ko=category_ko,
                description=description,
            )
        except Exception:
            return None

    @staticmethod
    def _detect_context(body: str, payload: str) -> str:
        escaped = html.escape(payload)
        if f'="{payload}"' in body or f"='{payload}'" in body:
            return "attribute"
        if payload in body and escaped in body:
            return "mixed"
        return "html"

    def _record(self, point: InputPoint, param_name: str, result: PayloadResult) -> None:
        key = f"{point.url}|{param_name}|{point.method}"
        finding = self.findings.get(key)
        if not finding:
            finding = Finding(url=point.url, parameter=param_name, method=point.method)
            self.findings[key] = finding
        finding.matches.append(result)

    def _record_stored(self, point: InputPoint, result: PayloadResult) -> None:
        key = f"{point.url}|[stored]|{point.method}"
        finding = self.findings.get(key)
        if not finding:
            finding = Finding(url=point.url, parameter="[stored]", method=point.method)
            self.findings[key] = finding
        finding.matches.append(result)

    def _test_stored(self, point: InputPoint) -> Optional[PayloadResult]:
        params = point.parameters.copy()
        unique_tag = f"s2n_stored_{int(time.time())}"
        payload = f"<script>alert('{unique_tag}')</script>"

        skip_names = {"btnsign", "btnsubmit", "btnclear", "submit"}

        self._refresh_tokens(point.url, params, point.method)

        updated = False
        for name in list(params.keys()):
            lower = name.lower()
            if any(keyword in lower for keyword in TOKEN_KEYWORDS):
                continue
            if lower in skip_names:
                continue
            params[name] = payload
            updated = True

        if not updated:
            return None

        try:
            if point.method.upper() == "POST":
                response = self.session.post(point.url, data=params, timeout=DEFAULT_TIMEOUT)
            else:
                response = self.session.get(point.url, params=params, timeout=DEFAULT_TIMEOUT)

            response.encoding = response.apparent_encoding
            self._update_tokens(response.text, params)
        except Exception:
            return None

        time.sleep(0.8)

        try:
            verify = self.session.get(point.url, timeout=DEFAULT_TIMEOUT)
            verify.encoding = verify.apparent_encoding
            body = verify.text
            escaped = html.escape(payload)
            if payload in body or unique_tag in body or escaped in body:
                return PayloadResult(
                    payload=payload,
                    context="stored",
                    category="stored",
                    category_ko="저장형",
                    description="Payload persisted and reflected on subsequent view",
                )
        except Exception:
            return None

        return None

    def _ensure_authenticated(self, url: str) -> None:
        try:
            response = self.session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            response.encoding = response.apparent_encoding
            final_url = response.url.lower()
            if "login" in final_url or "dvwa" in final_url and "login" in response.text.lower():
                print("[!] Warning: Received login page. Please supply valid authentication cookies.")
        except Exception as exc:
            print(f"[!] Warning: Failed to verify authentication: {exc}")

    def scan(self, target_url: str, params: Optional[Dict[str, str]] = None, method: str = "GET") -> List[Dict]:
        print(f"\n[*] Target: {target_url}")
        points: List[InputPoint]

        if params is not None:
            points = [
                InputPoint(
                    url=target_url.split("?")[0],
                    method=method,
                    parameters=params or {},
                    source="manual",
                )
            ]
        else:
            print("[*] Detecting input points...")
            self._ensure_authenticated(target_url)
            points = self.detector.detect(target_url)
            print(f"[+] Found {len(points)} input point(s)")

        for point in points:
            print(f"\n[+] Testing {point.url} ({point.method}) -> {list(point.parameters.keys())}")
            for param_name in list(point.parameters.keys()):
                lower = param_name.lower()
                if any(keyword in lower for keyword in TOKEN_KEYWORDS):
                    continue
                print(f"  - Parameter: {param_name}")

                successes = 0
                for payload in self.payloads:
                    result = self._test_payload(point, param_name, payload)
                    if result:
                        successes += 1
                        self._record(point, param_name, result)
                print(f"    Successful payloads: {successes}")

            if point.method.upper() == "POST" and point.source == "form":
                stored_result = self._test_stored(point)
                if stored_result:
                    print("    Stored payload persisted")
                    self._record_stored(point, stored_result)

        return [finding.as_dict() for finding in self.findings.values()]

    def print_summary(self) -> None:
        findings = list(self.findings.values())
        if not findings:
            print("\n✅ No reflected XSS detected")
            return

        print(f"\n⚠️  Reflected XSS detected in {len(findings)} location(s)")
        for idx, finding in enumerate(findings, 1):
            print(f"\n[{idx}] {finding.url}")
            print(f"    Parameter: {finding.parameter}")
            print(f"    Method: {finding.method}")
            print(f"    Successful payloads: {len(finding.matches)}")


def _prompt(message: str) -> str:
    try:
        return input(message)
    except (KeyboardInterrupt, EOFError):
        print("\nAborted by user.")
        sys.exit(0)


def main() -> int:
    payload_path = "xss_payloads.json"
    payload_file = payload_path if Path(payload_path).exists() else Path(__file__).parent / payload_path

    if not Path(payload_file).exists():
        print(f"Payload file not found: {payload_file}")
        return 1

    print("=" * 70)
    print("s2n-xss Reflected Scanner")
    print("=" * 70)

    target_url = _prompt("\n[>] Enter target URL: ").strip()
    if not target_url:
        print("No target provided.")
        return 1

    cookies_input = _prompt("[>] Enter cookies (key=value;key2=value2) or blank: ").strip()
    cookies = None
    if cookies_input:
        cookies = {}
        for pair in cookies_input.split(";"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    scanner = ReflectedScanner(str(payload_file), cookies)
    results = scanner.scan(target_url)
    scanner.print_summary()

    if results:
        save = _prompt("\n[?] Save results to JSON? (y/N): ").strip().lower()
        if save == "y":
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            out_path = Path.cwd() / f"xss_reflected_results_{timestamp}.json"
            with out_path.open("w", encoding="utf-8") as fp:
                json.dump(results, fp, ensure_ascii=False, indent=2)
            print(f"Saved to {out_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
