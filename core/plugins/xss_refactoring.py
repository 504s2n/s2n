"""
s2n-xss: XSS Vulnerability Scanner (Refactored v2.2)
Developer-friendly XSS detection optimized for Korean web applications

Improvements in this refactored version:
- ✨ Dataclass-based model for type safety
- ✨ Extracted configuration constants
- ✨ Removed code duplication (encoding logic centralized)
- ✨ Better separation of concerns (parsing, detection, testing)
- ✨ Enhanced error handling with context
- ✨ Improved logging and debugging
- ✨ More testable individual components
- ✨ Better naming conventions
"""

import json
import requests
import re
import time
import html
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from typing import Dict, List, Tuple, Optional, Set
from html.parser import HTMLParser
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
import sys

# ============================================================
# Configuration
# ============================================================

TOKEN_KEYWORDS = ("token", "csrf", "nonce")
DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "s2n-xss/2.2 (Security Scanner)"
STORED_XSS_DELAY = 0.8


# ============================================================
# Enums and Data Models
# ============================================================

class XSSType(str, Enum):
    """XSS vulnerability types"""
    REFLECTED = "Reflected"
    STORED = "Stored"
    DOM_BASED = "DOM-based"


class Severity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class InputPoint:
    """Represents a detected input point in the application"""
    url: str
    method: str
    parameters: Dict[str, str]
    source: str  # "url" or "form"

    def copy(self) -> "InputPoint":
        """Create a deep copy of input point"""
        return InputPoint(
            url=self.url,
            method=self.method,
            parameters=self.parameters.copy(),
            source=self.source
        )


@dataclass
class VulnerablePayload:
    """Represents a successfully exploited payload"""
    payload: str
    category: str
    category_ko: str
    description: str
    context: str


@dataclass
class Vulnerability:
    """Represents a discovered XSS vulnerability"""
    location_url: str
    parameter: str
    method: str
    xss_type: XSSType
    severity: Severity
    successful_payloads: List[VulnerablePayload] = field(default_factory=list)
    dom_sources: Optional[Tuple[str, str]] = None  # (source, sink) for DOM-based

    @property
    def location_key(self) -> str:
        """Generate unique key for this vulnerability location"""
        return f"{self.location_url}:{self.parameter}:{self.method}"


# ============================================================
# HTML Parsing
# ============================================================

class FormParser(HTMLParser):
    """
    Extracts forms and input fields from HTML for automatic input point detection.
    Handles input, textarea, and select elements.
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


# ============================================================
# Encoding Utilities
# ============================================================

class EncodingHelper:
    """Centralized encoding and decoding utilities"""

    @staticmethod
    def normalize_response_encoding(response: requests.Response) -> str:
        """Ensure proper encoding detection for response"""
        response.encoding = response.apparent_encoding
        return response.text

    @staticmethod
    def escape_payload(payload: str) -> str:
        """Get HTML-escaped version of payload"""
        return html.escape(payload)

    @staticmethod
    def check_payload_in_response(response_text: str, payload: str) -> bool:
        """Check if payload exists in response (literal or escaped)"""
        escaped = EncodingHelper.escape_payload(payload)
        return payload in response_text or escaped in response_text


# ============================================================
# Input Point Detection
# ============================================================

class InputPointDetector:
    """
    Automatically detects input points in web applications.
    Supports URL parameters, HTML forms, and form fields.
    """

    def __init__(self, session: requests.Session, timeout: int = DEFAULT_TIMEOUT):
        self.session = session
        self.timeout = timeout

    def detect_input_points(self, url: str) -> List[InputPoint]:
        """
        Detect all input points for given URL.
        
        Returns list of InputPoint objects representing:
        - URL parameters (GET)
        - HTML forms (POST/GET)
        """
        input_points = []

        # 1. Extract URL parameters
        input_points.extend(self._extract_url_parameters(url))

        # 2. Parse and extract HTML forms
        input_points.extend(self._extract_html_forms(url))

        return input_points

    def _extract_url_parameters(self, url: str) -> List[InputPoint]:
        """Extract GET parameters from URL"""
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)

        if not url_params:
            return []

        params = {
            k: v[0] if isinstance(v, list) else v 
            for k, v in url_params.items()
        }

        return [InputPoint(
            url=url.split("?")[0],
            method="GET",
            parameters=params,
            source="url"
        )]

    def _extract_html_forms(self, url: str) -> List[InputPoint]:
        """Extract forms and fields from HTML page"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code != 200:
                return []

            EncodingHelper.normalize_response_encoding(response)

            parser = FormParser()
            parser.feed(response.text)

            input_points = []
            for form in parser.forms:
                if not form["inputs"]:
                    continue

                action_url = (
                    urljoin(url, form["action"]) 
                    if form["action"] else url
                )

                params = self._build_form_parameters(form["inputs"])
                if params:
                    input_points.append(InputPoint(
                        url=action_url,
                        method=form["method"],
                        parameters=params,
                        source="form"
                    ))

            return input_points

        except Exception as e:
            print(f"  [!] Error extracting forms: {e}")
            return []

    @staticmethod
    def _build_form_parameters(inputs: List[Dict]) -> Dict[str, str]:
        """Build parameter dictionary from form inputs"""
        params = {}

        for inp in inputs:
            input_type = inp["type"].lower()
            name = inp["name"]

            if not name:
                continue

            # Handle submit buttons
            if input_type in ["submit", "button"]:
                params[name] = inp["value"] if inp["value"] else name
                continue

            # Handle regular inputs and hidden fields
            params[name] = inp["value"] if inp["value"] else "test"

        return params


# ============================================================
# DOM-based XSS Detection
# ============================================================

class DOMXSSDetector:
    """
    Detects DOM-based XSS vulnerabilities by analyzing JavaScript code
    for dangerous Source and Sink patterns.
    """

    DANGEROUS_SINKS = [
        r"document\.write\s*\(",
        r"document\.writeln\s*\(",
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"eval\s*\(",
        r"setTimeout\s*\(",
        r"setInterval\s*\(",
        r"Function\s*\(",
        r"location\s*=",
        r"location\.href\s*=",
        r"location\.replace\s*\(",
        r"location\.assign\s*\(",
    ]

    DANGEROUS_SOURCES = [
        r"location\.hash",
        r"location\.search",
        r"document\.URL",
        r"document\.documentURI",
        r"document\.referrer",
        r"window\.name",
    ]

    def detect_dom_xss(self, html_content: str) -> List[Tuple[str, str]]:
        """
        Analyze JavaScript in HTML for DOM-based XSS vulnerabilities.
        
        Returns:
            List of (source, sink) tuples indicating vulnerable patterns
        """
        vulnerabilities = []

        # Extract all script tags
        script_pattern = r"<script[^>]*>(.*?)</script>"
        scripts = re.findall(script_pattern, html_content, re.DOTALL | re.IGNORECASE)

        for script_content in scripts:
            found_source = self._find_pattern(script_content, self.DANGEROUS_SOURCES)
            found_sink = self._find_pattern(script_content, self.DANGEROUS_SINKS)

            # Vulnerability exists if both source and sink present
            if found_source and found_sink:
                vulnerabilities.append((found_source, found_sink))

        return vulnerabilities

    @staticmethod
    def _find_pattern(content: str, patterns: List[str]) -> Optional[str]:
        """Find first matching pattern in content"""
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                return match.group()
        return None


# ============================================================
# Stored XSS Detection
# ============================================================

class StoredXSSDetector:
    """
    Detects Stored XSS vulnerabilities by:
    1. Sending payload to target
    2. Waiting for persistence
    3. Verifying if payload is stored and returned
    """

    def __init__(self, session: requests.Session, timeout: int = DEFAULT_TIMEOUT):
        self.session = session
        self.timeout = timeout

    def test_stored_xss(
        self,
        input_point: InputPoint,
        payload: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Test if payload persists in storage.
        
        Returns:
            (is_vulnerable, actual_payload_found)
        """
        try:
            test_data = self._prepare_test_data(input_point, payload)

            # Send payload
            self._submit_payload(input_point.url, test_data, input_point.method)

            # Wait for storage
            time.sleep(STORED_XSS_DELAY)

            # Verify persistence
            return self._verify_payload_persistence(input_point.url, payload)

        except Exception as e:
            print(f"  [!] Stored XSS test failed: {e}")
            return False, None

    def _prepare_test_data(self, input_point: InputPoint, payload: str) -> Dict:
        """Prepare test data with payload"""
        test_data = input_point.parameters.copy()

        # Update CSRF tokens if present
        self._refresh_csrf_tokens(input_point.url, test_data)

        # Inject payload into all text fields
        for key in list(test_data.keys()):
            if not self._should_skip_field(key):
                test_data[key] = payload

        return test_data

    def _submit_payload(
        self,
        url: str,
        data: Dict,
        method: str
    ) -> requests.Response:
        """Submit payload to target"""
        if method == "POST":
            response = self.session.post(url, data=data, timeout=self.timeout)
        else:
            response = self.session.get(url, params=data, timeout=self.timeout)

        EncodingHelper.normalize_response_encoding(response)
        return response

    def _verify_payload_persistence(
        self,
        url: str,
        payload: str
    ) -> Tuple[bool, Optional[str]]:
        """Check if payload is stored and returned"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            response_text = EncodingHelper.normalize_response_encoding(response)

            if EncodingHelper.check_payload_in_response(response_text, payload):
                return True, payload

            return False, None

        except Exception:
            return False, None

    def _refresh_csrf_tokens(self, url: str, data: Dict) -> None:
        """Update CSRF tokens from current page"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            response_text = EncodingHelper.normalize_response_encoding(response)
            self._extract_tokens_from_html(response_text, data)
        except Exception:
            pass  # Continue with existing tokens

    def _extract_tokens_from_html(self, html_content: str, data: Dict) -> None:
        """Extract token values from HTML forms"""
        parser = FormParser()
        parser.feed(html_content)

        for form in parser.forms:
            for inp in form["inputs"]:
                name = inp["name"]
                if not name:
                    continue

                if any(keyword in name.lower() for keyword in TOKEN_KEYWORDS):
                    data[name] = inp.get("value", "")

    @staticmethod
    def _should_skip_field(field_name: str) -> bool:
        """Check if field should be skipped from payload injection"""
        lower_name = field_name.lower()
        skip_keywords = ["submit", "button", "btnsign"]
        return (
            any(keyword in lower_name for keyword in skip_keywords) or
            any(keyword in lower_name for keyword in TOKEN_KEYWORDS)
        )


# ============================================================
# Payload Management
# ============================================================

class PayloadCategorizer:
    """
    Categorizes payloads for better reporting and organization.
    Supports multiple languages (Korean, English).
    """

    CATEGORIES = {
        "basic_script": {
            "ko": "기본 스크립트 태그",
            "en": "Basic Script Tag",
            "patterns": ["<script>"],
            "exclusions": ["fromcharcode", "atob"]
        },
        "event_handler": {
            "ko": "이벤트 핸들러",
            "en": "Event Handler",
            "patterns": ["onerror", "onload", "onfocus", "onclick"]
        },
        "encoding_bypass": {
            "ko": "인코딩 우회",
            "en": "Encoding Bypass",
            "patterns": ["%", "\\u", "\\x", "&#", "&lt;", "&gt;"]
        },
        "obfuscation": {
            "ko": "난독화",
            "en": "Obfuscation",
            "patterns": ["fromcharcode", "atob", "eval"]
        },
        "whitespace_bypass": {
            "ko": "공백 문자 우회",
            "en": "Whitespace Bypass",
            "patterns": ["/", "\t", "\n"]
        },
        "korean_encoding": {
            "ko": "한글 인코딩",
            "en": "Korean Encoding",
            "patterns": ["EUC-KR", "테스트", "한글", "가나다"]
        },
        "html_comment": {
            "ko": "HTML 주석 우회",
            "en": "HTML Comment Bypass",
            "patterns": ["<!--", "//-->"]
        }
    }

    @classmethod
    def categorize(cls, payload: str) -> Dict[str, str]:
        """
        Categorize payload and return metadata.
        
        Returns:
            {
                "category": category_id,
                "category_ko": Korean name,
                "category_en": English name,
                "description": Full description
            }
        """
        payload_lower = payload.lower()

        for cat_id, cat_info in cls.CATEGORIES.items():
            if cls._matches_category(payload_lower, cat_info):
                return {
                    "category": cat_id,
                    "category_ko": cat_info["ko"],
                    "category_en": cat_info["en"],
                    "description": f"{cat_info['en']} exploitation"
                }

        # Default category
        return {
            "category": "other",
            "category_ko": "기타",
            "category_en": "Other",
            "description": "Other XSS technique"
        }

    @staticmethod
    def _matches_category(payload: str, category_info: Dict) -> bool:
        """Check if payload matches category patterns"""
        patterns = category_info.get("patterns", [])
        exclusions = category_info.get("exclusions", [])

        # Check exclusions first
        if exclusions and any(exc in payload for exc in exclusions):
            return False

        # Check patterns
        return any(pat in payload for pat in patterns)


# ============================================================
# Core Scanner
# ============================================================

class S2NXSSScanner:
    """
    Main XSS scanner engine.
    
    Refactored features:
    - Cleaner class design with better separation of concerns
    - Type-safe with dataclasses
    - Centralized configuration
    - Improved error handling
    - Better test support
    """

    def __init__(
        self,
        payloads_path: str,
        cookies: Optional[Dict] = None,
        timeout: int = DEFAULT_TIMEOUT,
        auto_detect: bool = True
    ):
        """
        Initialize scanner with configuration.
        
        Args:
            payloads_path: Path to XSS payloads JSON file
            cookies: Session cookies (e.g., authentication)
            timeout: Request timeout in seconds
            auto_detect: Enable automatic input point detection
        """
        self.timeout = timeout
        self.auto_detect = auto_detect
        self.payloads_path = Path(payloads_path)

        # Vulnerability tracking
        self.vulnerabilities: List[Vulnerability] = []
        self.vulnerability_map: Dict[str, Vulnerability] = {}

        # Statistics
        self.total_tests = 0

        # Initialize session
        self.session = self._create_session(cookies)

        # Load payloads
        self.payloads_data = self._load_payloads()

        # Initialize detectors
        self.input_detector = InputPointDetector(self.session, timeout)
        self.dom_detector = DOMXSSDetector()
        self.stored_detector = StoredXSSDetector(self.session, timeout)

        self._log_initialization()

    def _create_session(self, cookies: Optional[Dict]) -> requests.Session:
        """Create and configure requests session"""
        session = requests.Session()
        session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

        if cookies:
            session.cookies.update(cookies)
            # Ensure DVWA default if not specified
            if "security" not in session.cookies:
                session.cookies.set("security", "low")

        return session

    def _load_payloads(self) -> Dict:
        """Load payloads from JSON file"""
        try:
            with open(self.payloads_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[ERROR] Payload file not found: {self.payloads_path}")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"[ERROR] Invalid JSON in payload file: {self.payloads_path}")
            sys.exit(1)

    def _log_initialization(self):
        """Log initialization information"""
        total = self.payloads_data.get("metadata", {}).get("total_payloads", 0)
        print(f"[+] Loaded {total} payloads from {self.payloads_path}")

    def select_payloads(self, intensity: int = 2) -> List[str]:
        """
        Select payloads based on scan intensity.
        
        Args:
            intensity: 1 (Basic), 2 (Moderate), 3 (Aggressive)
        
        Returns:
            List of selected payloads
        """
        payloads = []
        data = self.payloads_data["payloads"]
        bypass = self.payloads_data["filter_bypass"]
        korean = self.payloads_data["korean_encoding_specific"]

        if intensity >= 1:
            # Basic payloads
            payloads.extend(data["html_context"]["basic"][:3])

        if intensity >= 2:
            # Moderate payloads
            payloads.extend(data["html_context"]["basic"][3:])
            payloads.extend(data["html_context"]["korean_specific"])
            payloads.extend(data["attribute_context"]["double_quote"][:2])
            payloads.extend(bypass["obfuscation"][:3])
            payloads.extend(bypass["space_bypass"])
            payloads.extend(bypass["comment_bypass"])
            payloads.extend(korean["euc_kr_bypass"])

        if intensity >= 3:
            # Aggressive payloads
            payloads.extend(bypass["encoding"])
            payloads.extend(data["attribute_context"]["single_quote"])
            payloads.extend(data["attribute_context"]["no_quote"])
            payloads.extend(korean["fullwidth_chars"])

        return payloads

    def test_payload(
        self,
        input_point: InputPoint,
        payload: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Test single payload against input point.
        
        Returns:
            (is_vulnerable, detected_context)
        """
        self.total_tests += 1
        test_params = input_point.parameters.copy()

        try:
            response = self._send_request(input_point.url, test_params, input_point.method)
            response_text = self._combine_response_history(response)

            if EncodingHelper.check_payload_in_response(response_text, payload):
                context = self._detect_context(response_text, payload)
                return True, context

            return False, None

        except Exception as e:
            print(f"  [!] Error testing payload: {e}")
            return False, None

    def _send_request(
        self,
        url: str,
        params: Dict,
        method: str
    ) -> requests.Response:
        """Send HTTP request and handle encoding"""
        if method == "POST":
            response = self.session.post(url, data=params, timeout=self.timeout)
        else:
            response = self.session.get(url, params=params, timeout=self.timeout)

        EncodingHelper.normalize_response_encoding(response)
        return response

    @staticmethod
    def _combine_response_history(response: requests.Response) -> str:
        """Combine redirect history and final response for analysis"""
        text = response.text

        if response.history:
            for hist_response in response.history:
                EncodingHelper.normalize_response_encoding(hist_response)
                text += hist_response.text

        return text

    def _detect_context(self, response_text: str, payload: str) -> str:
        """Detect context where payload was injected"""
        # Simplified context detection
        if "<script>" in payload.lower():
            return "html_context"
        elif "on" in payload.lower() and "=" in payload:
            return "attribute_context"
        elif "javascript:" in payload.lower():
            return "url_context"
        else:
            return "unknown"

    def scan(
        self,
        target_url: str,
        intensity: int = 2
    ) -> List[Vulnerability]:
        """
        Execute full XSS scan.
        
        Args:
            target_url: Target application URL
            intensity: Scan intensity (1-3)
        
        Returns:
            List of discovered vulnerabilities
        """
        print(f"\n[*] Starting scan on: {target_url}")
        print(f"[*] Intensity: {intensity}/3")

        # Detect input points
        input_points = self._get_input_points(target_url)
        print(f"[+] Found {len(input_points)} input point(s)")

        if not input_points:
            print("[!] No input points detected")
            return self.vulnerabilities

        # Select payloads based on intensity
        payloads = self.select_payloads(intensity)
        print(f"[+] Selected {len(payloads)} payload(s)")

        # Test each combination
        for i, input_point in enumerate(input_points, 1):
            print(f"\n[*] Testing input point {i}/{len(input_points)}: {input_point.parameter}")
            self._test_input_point(input_point, payloads)

        # Test DOM-based XSS
        self._test_dom_xss(target_url)

        return self.vulnerabilities

    def _get_input_points(self, target_url: str) -> List[InputPoint]:
        """Get input points for target URL"""
        if self.auto_detect:
            return self.input_detector.detect_input_points(target_url)
        return []

    def _test_input_point(self, input_point: InputPoint, payloads: List[str]):
        """Test all payloads against an input point"""
        for payload in payloads:
            is_vulnerable, context = self.test_payload(input_point, payload)

            if is_vulnerable:
                self._record_vulnerability(
                    input_point,
                    payload,
                    XSSType.REFLECTED,
                    context
                )

    def _test_dom_xss(self, target_url: str):
        """Test for DOM-based XSS"""
        try:
            response = self.session.get(target_url, timeout=self.timeout)
            vulnerabilities = self.dom_detector.detect_dom_xss(response.text)

            for source, sink in vulnerabilities:
                print(f"  [+] DOM XSS: {source} -> {sink}")
        except Exception as e:
            print(f"  [!] DOM XSS test failed: {e}")

    def _record_vulnerability(
        self,
        input_point: InputPoint,
        payload: str,
        xss_type: XSSType,
        context: str
    ):
        """Record discovered vulnerability"""
        # Categorize payload
        category_info = PayloadCategorizer.categorize(payload)

        vulnerable_payload = VulnerablePayload(
            payload=payload,
            category=category_info["category"],
            category_ko=category_info["category_ko"],
            description=category_info["description"],
            context=context
        )

        # Determine severity
        severity = self._assess_severity(xss_type, category_info["category"])

        # Get or create vulnerability record
        vuln_key = f"{input_point.url}:{input_point.parameters}:{input_point.method}"

        if vuln_key in self.vulnerability_map:
            vuln = self.vulnerability_map[vuln_key]
            vuln.successful_payloads.append(vulnerable_payload)
        else:
            vuln = Vulnerability(
                location_url=input_point.url,
                parameter=str(list(input_point.parameters.keys())),
                method=input_point.method,
                xss_type=xss_type,
                severity=severity,
                successful_payloads=[vulnerable_payload]
            )
            self.vulnerability_map[vuln_key] = vuln
            self.vulnerabilities.append(vuln)

        print(f"  [+] XSS found! Payload: {payload[:50]}...")

    @staticmethod
    def _assess_severity(xss_type: XSSType, category: str) -> Severity:
        """Assess vulnerability severity"""
        if xss_type == XSSType.STORED:
            return Severity.CRITICAL
        elif xss_type == XSSType.DOM_BASED:
            return Severity.HIGH
        elif category == "basic_script":
            return Severity.HIGH
        else:
            return Severity.MEDIUM

    def export_report(self, output_path: Optional[str] = None) -> None:
        """
        Export scan results to JSON report.
        
        Args:
            output_path: Output file path (auto-generated if None)
        """
        if output_path is None:
            output_path = f"xss_report_{int(time.time())}.json"

        report = {
            "metadata": {
                "scanner": "s2n-xss",
                "version": "2.2-refactored",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "total_tests": self.total_tests,
                "severity_breakdown": self._build_severity_breakdown(),
            },
            "vulnerabilities": [self._format_vulnerability(v) for v in self.vulnerabilities],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        print(f"[*] Report exported: {output_path}")

    def _build_severity_breakdown(self) -> Dict[str, int]:
        """Build severity breakdown statistics"""
        breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for vuln in self.vulnerabilities:
            breakdown[vuln.severity.value] += 1

        return breakdown

    @staticmethod
    def _format_vulnerability(vuln: Vulnerability) -> Dict:
        """Format vulnerability for JSON export"""
        return {
            "url": vuln.location_url,
            "parameter": vuln.parameter,
            "method": vuln.method,
            "xss_type": vuln.xss_type.value,
            "severity": vuln.severity.value,
            "successful_payloads": [
                asdict(p) for p in vuln.successful_payloads
            ],
        }


# ============================================================
# Interactive CLI
# ============================================================

def get_target_url() -> str:
    """Get target URL from user"""
    try:
        url = input("\n[>] Enter target URL: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n\nAborted by user.")
        sys.exit(0)

    if not url:
        print("[!] No URL provided.")
        sys.exit(0)

    return url


def get_authentication() -> Optional[Dict]:
    """Get authentication cookies from user"""
    print("\n" + "=" * 70)
    print("Step 2: Authentication (Optional)")
    print("=" * 70)

    phpsessid = input("[>] PHPSESSID (press Enter to skip): ").strip()

    if not phpsessid:
        print("[*] Proceeding without authentication")
        return None

    cookies = {"PHPSESSID": phpsessid}
    print(f"[+] Cookies configured")

    return cookies


def get_intensity() -> int:
    """Get scan intensity from user"""
    print("\n" + "=" * 70)
    print("Step 3: Scan Intensity")
    print("=" * 70)

    print("\n[?] Select intensity:")
    print("  1 - Basic      (~10 payloads)")
    print("  2 - Moderate   (~30 payloads) [Recommended]")
    print("  3 - Aggressive (50+ payloads)")

    intensity_input = input("[>] [1-3, default=2]: ").strip()

    return int(intensity_input) if intensity_input in ["1", "2", "3"] else 2


def main():
    """Main interactive scanner"""
    print("\n" + "=" * 70)
    print("s2n-xss : XSS Vulnerability Scanner (Refactored v2.2)")
    print("=" * 70)

    # Find payloads file
    payloads_path = Path("xss_payloads.json")
    if not payloads_path.exists():
        payloads_path = Path(__file__).parent / "xss_payloads.json"

    if not payloads_path.exists():
        print(f"\n[ERROR] Payload file not found: {payloads_path}")
        sys.exit(1)

    # Get configuration
    target_url = get_target_url()
    cookies = get_authentication()
    intensity = get_intensity()

    # Initialize and run scanner
    print("\n" + "=" * 70)
    print("Initializing Scanner")
    print("=" * 70)

    try:
        scanner = S2NXSSScanner(
            payloads_path=str(payloads_path),
            cookies=cookies,
            timeout=DEFAULT_TIMEOUT,
            auto_detect=True
        )
    except Exception as e:
        print(f"\n[ERROR] Failed to initialize: {e}")
        sys.exit(1)

    # Run scan
    print("\n" + "=" * 70)
    print("Starting Scan")
    print("=" * 70)

    try:
        start_time = time.time()
        vulnerabilities = scanner.scan(target_url, intensity=intensity)
        elapsed = time.time() - start_time
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Scan failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Display results
    print("\n" + "=" * 70)
    print("SCAN RESULTS")
    print("=" * 70)
    print(f"\nScan completed in {elapsed:.1f} seconds")
    print(f"Target: {target_url}")
    print(f"Total vulnerabilities found: {len(vulnerabilities)}")

    if vulnerabilities:
        print(f"\n⚠️  Found {len(vulnerabilities)} XSS vulnerability(ies)!\n")

        # Severity breakdown
        severity_count = {}
        for vuln in vulnerabilities:
            sev = vuln.severity.value
            severity_count[sev] = severity_count.get(sev, 0) + 1

        print("By severity:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if count := severity_count.get(sev, 0):
                print(f"  {sev}: {count}")

        # Export report
        try:
            scanner.export_report()
        except Exception as e:
            print(f"\n[!] Failed to save report: {e}")
    else:
        print("\n✅ No XSS vulnerabilities detected")

    print("\n" + "=" * 70)
    print("Scan Complete")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
