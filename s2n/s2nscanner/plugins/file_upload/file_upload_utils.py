import re
import os
import uuid
import tempfile
import requests
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from s2n.s2nscanner.interfaces import (
    Finding,
    PluginContext,
    Severity,
)
from s2n.s2nscanner.logger import get_logger
from s2n.s2nscanner.crawler import crawl_recursive
from s2n.s2nscanner.auth.dvwa_adapter import DVWAAdapter

logger = get_logger("plugins.file_upload.utils")


class Form:
    def __init__(self, attrs: Dict[str, str]):
        self.attrs = attrs
        self.inputs: List[Dict[str, str]] = []

    def get(self, key: str, default: Any = None) -> Any:
        return self.attrs.get(key, default)


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: List[Form] = []
        self.current_form: Optional[Form] = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "form":
            self.current_form = Form(attrs_dict)
        elif tag == "input" and self.current_form is not None:
            self.current_form.inputs.append(attrs_dict)

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


class RobustDVWAAdapter(DVWAAdapter):
    """DVWAAdapter subclass with more robust token extraction."""

    def _extract_user_token(self, text: str) -> Optional[str]:
        # 1. Try original regex
        token = super()._extract_user_token(text)
        if token:
            return token

        # 2. Try FormParser for robust HTML parsing
        try:
            parser = FormParser()
            parser.feed(text)
            for form in parser.forms:
                for inp in form.inputs:
                    if inp.get("name") == "user_token":
                        return inp.get("value")
        except Exception:
            pass

        # 3. Try alternative regex (value before name)
        match = re.search(
            r'value=["\']([^"\']+)["\']\s+name=["\']user_token["\']',
            text,
            re.IGNORECASE,
        )
        if match:
            return match.group(1)

        return None


def find_upload_form(content: str) -> Optional[Form]:
    """HTML에서 파일 업로드 폼을 찾습니다."""
    parser = FormParser()
    parser.feed(content)

    for form in parser.forms:
        if any(inp.get("type") == "file" for inp in form.inputs):
            return form
    return None


def find_login_form(content: str) -> Optional[Form]:
    """HTML에서 로그인 폼으로 보이는 것을 찾습니다."""
    parser = FormParser()
    parser.feed(content)

    for form in parser.forms:
        if any(inp.get("type") == "password" for inp in form.inputs):
            action = str(form.get("action", "")).lower()
            if "login" in action or "signin" in action:
                return form
    return None


def collect_form_data(form: Form) -> dict:
    """폼에서 모든 입력 필드(hidden 포함)의 데이터를 수집합니다."""
    data = {}
    for input_attrs in form.inputs:
        name = input_attrs.get("name")
        value = input_attrs.get("value", "")
        # type이 submit, button, reset이 아닌 경우에만 추가
        if name and input_attrs.get("type") not in ["submit", "button", "reset"]:
            data[name] = value
    return data


def guess_uploaded_urls(response, base_url: str) -> list[str]:
    """업로드 성공 후 파일이 있을 만한 URL들을 추측합니다."""
    urls = set()

    # 1. 응답 본문에서 링크 찾기
    hrefs = re.findall(r'<a\s+(?:[^>]*?\s+)?href=(["\'])(.*?)\1', response.text, re.I)
    for _, href in hrefs:
        full_url = urljoin(base_url, str(href))
        urls.add(full_url)

    # 2. 일반적인 업로드 경로 추측
    parsed_base = urlparse(base_url)
    filename = "test.php"  # A common test filename
    common_paths = ["uploads/", "files/", "images/", "./"]
    for path in common_paths:
        # action URL 기준
        guess = urljoin(base_url, path + filename)
        urls.add(guess)
        # 루트 기준
        root_guess = f"{parsed_base.scheme}://{parsed_base.netloc}/{path}{filename}"
        urls.add(root_guess)

    # 3. 응답 텍스트에서 URL 같은 문자열 찾기
    found_in_text = re.findall(r'["\'](/[^"\\]+)["\']', response.text)
    for path in found_in_text:
        if path.endswith(
            (".php", ".jpg", ".png", ".txt")
        ):  # Add more extensions if needed
            urls.add(urljoin(base_url, path))

    return list(urls)


def authenticate_if_needed(
    plugin_context: PluginContext,
    initial_response: requests.Response,
    http_client,
    stats: dict,
) -> requests.Response:
    """
    Checks for a login form in the initial response and attempts authentication if configured.
    Returns the response after authentication (or the original if not needed/failed).
    """
    login_form = find_login_form(initial_response.text)
    if not login_form:
        return initial_response

    logger.info("Login form detected. Checking for authentication configuration...")
    auth_config = plugin_context.scan_context.config.auth_config

    if not (auth_config and auth_config.username and auth_config.password):
        logger.info("No authentication credentials configured.")
        return initial_response

    logger.info("Attempting DVWA authentication with configured credentials.")
    # 로그인 폼의 action을 통해 정확한 로그인 URL 파악
    action = login_form.get("action")
    # resp.url은 리다이렉션 후의 최종 URL (로그인 페이지일 가능성 높음)
    login_full_url = (
        urljoin(initial_response.url, action) if action else initial_response.url
    )

    parsed_login = urlparse(login_full_url)
    base_url = f"{parsed_login.scheme}://{parsed_login.netloc}"
    login_path = parsed_login.path
    logger.info("Login URL: %s", login_full_url)
    logger.info("Login Path: %s", login_path)
    logger.info("Base URL: %s", base_url)

    # index_path 추론: login.php와 같은 위치의 index.php 가정
    if "/" in login_path:
        parent_dir = login_path.rsplit("/", 1)[0]
        index_path = f"{parent_dir}/index.php"
    else:
        index_path = "/index.php"

    adapter = RobustDVWAAdapter(
        base_url=base_url,
        login_path=login_path,
        index_path=index_path,
        client=http_client,
    )
    creds = [(auth_config.username, auth_config.password)]

    if adapter.ensure_authenticated(creds):
        logger.info("DVWA authentication successful. Retrying target URL.")
        target_url = plugin_context.scan_context.config.target_url
        resp = http_client.get(target_url)
        stats["requests_sent"] += 1
        return resp
    else:
        logger.warning("DVWA authentication failed.")
        return initial_response


def find_upload_form_recursive(
    target_url: str,
    http_client,
    plugin_context: PluginContext,
    initial_response: requests.Response,
    stats: dict,
) -> Tuple[Optional[Form], str]:
    """
    Finds an upload form on the target URL or by crawling if not found initially.
    Returns (form, found_at_url).
    """
    # 1. Check initial page
    form = find_upload_form(initial_response.text)
    if form:
        return form, target_url

    # 2. Crawl if not found
    logger.info("현재 페이지에 업로드 폼이 없습니다. 크롤러를 시작합니다.")
    max_depth = plugin_context.scan_context.config.scanner_config.crawl_depth

    # 크롤러를 사용하여 URL 수집
    scanned_urls = crawl_recursive(target_url, http_client, depth=max_depth)

    for url in scanned_urls:
        if url == target_url:
            continue

        try:
            logger.info("Checking for upload form at: %s", url)
            r = http_client.get(url, timeout=10)
            stats["requests_sent"] += 1
            stats["urls_scanned"] += 1

            f = find_upload_form(r.text)
            if f:
                logger.info("Found upload form at: %s", url)
                return f, url
        except Exception as e:
            logger.warning("Error checking URL %s: %s", url, e)
            continue

    return None, target_url


def upload_test_files(
    http_client,
    action_url: str,
    data: dict,
    file_field_name: str,
    plugin_name: str,
    stats: dict,
) -> List[Finding]:
    """
    Attempts to upload various test files and checks for vulnerabilities.
    """
    findings: List[Finding] = []

    # 안전한 테스트 파일 생성 (txt 파일로 변경하여 시스템 손상 방지)
    test_content = "S2N_UPLOAD_TEST_MARKER_" + uuid.uuid4().hex[:8]
    tmp_dir = tempfile.gettempdir()

    # 여러 파일 타입으로 테스트하여 취약점 탐지율 향상
    test_files = [
        ("test_upload.txt", "text/plain"),
        ("test_upload.php", "application/x-php"),
        ("test_upload.jpg.php", "image/jpeg"),
    ]

    uploaded_successfully = False
    vulnerable_url = None
    last_response = None

    for filename, mime_type in test_files:
        test_path = os.path.join(tmp_dir, filename)

        try:
            # 파일 생성
            with open(test_path, "w", encoding="utf-8") as f:
                f.write(test_content)

            # 파일 업로드 시도
            with open(test_path, "rb") as fobj:
                files = {file_field_name: (filename, fobj, mime_type)}
                try:
                    response = http_client.post(
                        action_url, data=data, files=files, timeout=15
                    )
                    stats["requests_sent"] += 1
                    uploaded_successfully = True
                    last_response = response
                except requests.exceptions.Timeout:
                    logger.warning("Upload request timed out for %s", filename)
                    continue
                except requests.exceptions.RequestException as e:
                    logger.warning("Upload request failed for %s: %s", filename, e)
                    continue

            # 업로드된 파일 위치 추측 및 확인
            candidates = guess_uploaded_urls(response, action_url)

            for url in candidates:
                try:
                    r = http_client.get(url, timeout=10)
                    stats["requests_sent"] += 1

                    # 테스트 마커가 응답에 포함되어 있는지 확인
                    if r.status_code == 200 and test_content in r.text:
                        vulnerable_url = url
                        severity = (
                            Severity.HIGH
                            if filename.endswith(".php")
                            else Severity.MEDIUM
                        )

                        findings.append(
                            Finding(
                                id=f"file-upload-{uuid.uuid4()}",
                                plugin=plugin_name,
                                severity=severity,
                                title="File Upload Vulnerability Detected",
                                description=f"Arbitrary file upload is possible. A test file ({filename}) was uploaded and is accessible at {url}. "
                                f"This could allow attackers to upload malicious files.",
                                url=url,
                                evidence=f"Test marker '{test_content}' found in response from {url}",
                                timestamp=datetime.now(),
                                remediation="Implement proper file type validation, restrict upload directories, and sanitize file names.",
                            )
                        )
                        break
                except requests.exceptions.RequestException:
                    continue

            if vulnerable_url:
                break

        finally:
            # 임시 파일 정리
            if test_path and os.path.exists(test_path):
                try:
                    os.remove(test_path)
                    logger.debug("Removed temp file: %s", test_path)
                except Exception as e:
                    logger.warning("Could not remove temp file %s: %s", test_path, e)

    # 업로드는 성공했지만 파일 위치를 찾지 못한 경우
    if uploaded_successfully and not findings and last_response:
        # 응답에서 성공 메시지 확인
        if re.search(
            r"successfully uploaded|file uploaded|upload complete|uploaded successfully|succesfully uploaded",
            last_response.text,
            flags=re.I,
        ):
            findings.append(
                Finding(
                    id=f"file-upload-potential-{uuid.uuid4()}",
                    plugin=plugin_name,
                    severity=Severity.MEDIUM,
                    title="Potential File Upload Vulnerability",
                    description="Server reported a successful upload, but the file's location could not be determined. "
                    "This may still indicate a file upload vulnerability.",
                    url=action_url,
                    evidence=last_response.text[:500],
                    timestamp=datetime.now(),
                    remediation="Verify file upload restrictions and implement proper validation.",
                )
            )

    return findings
