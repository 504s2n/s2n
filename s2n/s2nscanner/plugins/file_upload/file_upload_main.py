from typing import List
from datetime import datetime
from s2n.s2nscanner.plugins.csrf.csrf_constants import USER_AGENT

import os
import re
import tempfile
import uuid
from urllib.parse import urljoin, urlparse


import requests

# interfaces에서 제공되는 타입 사용
from s2n.s2nscanner.interfaces import (
    Finding,
    PluginContext,
    PluginError,
    PluginResult,
    PluginStatus,
    Severity,
)
from s2n.s2nscanner.logger import get_logger
from s2n.s2nscanner.crawler import crawl_recursive
from s2n.s2nscanner.auth.dvwa_adapter import DVWAAdapter


# 헬퍼 함수 임포트: 패키지 실행/모듈 실행/직접 실행 모두 지원
try:
    from .file_upload_utils import (
        collect_form_data,
        find_upload_form,
        find_login_form,
        guess_uploaded_urls,
    )
except ImportError:
    from file_upload_utils import (
        collect_form_data,
        find_upload_form,
        find_login_form,
        guess_uploaded_urls,
    )

logger = get_logger("plugins.file_upload")


class FileUploadPlugin:
    name = "file_upload"
    description = "파일 업로드 취약점을 탐지합니다."

    def __init__(self, config: PluginContext | None = None):
        self.config = config or {}
        self.plugin_context = self.config or {}

    def run(self, plugin_context: PluginContext) -> PluginResult | PluginError:
        start_time = datetime.now()
        findings: List[Finding] = []
        stats = {"requests_sent": 0, "urls_scanned": 0}
        target_url = plugin_context.scan_context.config.target_url
        http_client = plugin_context.scan_context.http_client
        if "User-Agent" not in http_client.s.headers:
            http_client.s.headers.update({"User-Agent": USER_AGENT})

        try:
            logger.info("[*] Fetching upload page: %s", target_url)
            resp = http_client.get(target_url, timeout=10)
            stats["requests_sent"] += 1
            stats["urls_scanned"] += 1

            form = find_upload_form(resp.text)
            found_at = target_url

            # 로그인 폼이 발견되면 인증 시도
            if form is None:
                login_form = find_login_form(resp.text)
                if login_form:
                    logger.info(
                        "Login form detected. Checking for authentication configuration..."
                    )
                    auth_config = plugin_context.scan_context.config.auth_config

                    if auth_config and auth_config.username and auth_config.password:
                        logger.info(
                            "Attempting DVWA authentication with configured credentials."
                        )
                        # 로그인 폼의 action을 통해 정확한 로그인 URL 파악
                        action = login_form.get("action")
                        # resp.url은 리다이렉션 후의 최종 URL (로그인 페이지일 가능성 높음)
                        login_full_url = (
                            urljoin(resp.url, action) if action else resp.url
                        )

                        parsed_login = urlparse(login_full_url)
                        base_url = f"{parsed_login.scheme}://{parsed_login.netloc}"
                        login_path = parsed_login.path

                        # index_path 추론: login.php와 같은 위치의 index.php 가정
                        if "/" in login_path:
                            parent_dir = login_path.rsplit("/", 1)[0]
                            index_path = f"{parent_dir}/index.php"
                        else:
                            index_path = "/index.php"

                        adapter = DVWAAdapter(
                            base_url=base_url,
                            login_path=login_path,
                            index_path=index_path,
                            client=http_client,
                        )
                        creds = [(auth_config.username, auth_config.password)]

                        if adapter.ensure_authenticated(creds):
                            logger.info(
                                "DVWA authentication successful. Retrying target URL."
                            )
                            resp = http_client.get(target_url)
                            stats["requests_sent"] += 1
                            form = find_upload_form(resp.text)
                        else:
                            logger.warning("DVWA authentication failed.")
                    else:
                        logger.info("No authentication credentials configured.")

            # 현재 페이지에 폼이 없으면 크롤러를 사용하여 탐색
            if form is None:
                logger.info("현재 페이지에 업로드 폼이 없습니다. 크롤러를 시작합니다.")
                max_depth = (
                    plugin_context.scan_context.config.scanner_config.crawl_depth
                )

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
                            form = f
                            found_at = url
                            logger.info("Found upload form at: %s", url)
                            break
                    except Exception as e:
                        logger.warning("Error checking URL %s: %s", url, e)
                        continue

            if form is None:
                logger.info("No upload form found on the page.")
                return PluginResult(
                    plugin_name=self.name,
                    status=PluginStatus.SUCCESS,
                    findings=findings,
                    start_time=start_time,
                    end_time=datetime.now(),
                    duration_seconds=(datetime.now() - start_time).total_seconds(),
                    urls_scanned=stats["urls_scanned"],
                    requests_sent=stats["requests_sent"],
                )

            action = form.get("action") or found_at
            action_url = urljoin(str(found_at), str(action))
            method = str((form.get("method") or "post")).lower()
            logger.info(f"Action URL: {action_url}")
            logger.info(f"Method: {method}")

            if method != "post":
                logger.warning("Form method is not POST (method=%s). Skipping.", method)
                return PluginResult(
                    plugin_name=self.name,
                    status=PluginStatus.SKIPPED,
                    start_time=start_time,
                    end_time=datetime.now(),
                    duration_seconds=(datetime.now() - start_time).total_seconds(),
                )

            data = collect_form_data(form)
            file_input = next((i for i in form.inputs if i.get("type") == "file"), None)
            file_field_name = (
                str(file_input.get("name")) or "file" if file_input else "file"
            )

            if not file_input or not file_field_name:
                logger.info("No file input field found in the upload form.")
                return PluginResult(
                    plugin_name=self.name,
                    status=PluginStatus.SUCCESS,
                    findings=findings,
                    start_time=start_time,
                    end_time=datetime.now(),
                    duration_seconds=(datetime.now() - start_time).total_seconds(),
                    urls_scanned=stats["urls_scanned"],
                    requests_sent=stats["requests_sent"],
                )

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
                        except requests.exceptions.Timeout:
                            logger.warning("Upload request timed out for %s", filename)
                            continue
                        except requests.exceptions.RequestException as e:
                            logger.warning(
                                "Upload request failed for %s: %s", filename, e
                            )
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
                                        plugin=self.name,
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
                            logger.warning(
                                "Could not remove temp file %s: %s", test_path, e
                            )

            # 업로드는 성공했지만 파일 위치를 찾지 못한 경우
            if uploaded_successfully and not findings:
                # 응답에서 성공 메시지 확인
                if re.search(
                    r"successfully uploaded|file uploaded|upload complete|uploaded successfully|succesfully uploaded",
                    response.text,
                    flags=re.I,
                ):
                    findings.append(
                        Finding(
                            id=f"file-upload-potential-{uuid.uuid4()}",
                            plugin=self.name,
                            severity=Severity.MEDIUM,
                            title="Potential File Upload Vulnerability",
                            description="Server reported a successful upload, but the file's location could not be determined. "
                            "This may still indicate a file upload vulnerability.",
                            url=action_url,
                            evidence=response.text[:500],
                            timestamp=datetime.now(),
                            remediation="Verify file upload restrictions and implement proper validation.",
                        )
                    )

        except requests.exceptions.ConnectionError as e:
            error_msg = str(e)
            # Check if this is a localhost connection issue (common in Docker)
            if "localhost" in target_url or "127.0.0.1" in target_url:
                helpful_msg = (
                    f"Connection refused to {target_url}. "
                    "If running inside Docker, 'localhost' refers to the container itself. "
                    "Try using 'host.docker.internal' (Docker Desktop) or the target container's name instead. "
                    f"Original error: {error_msg}"
                )
            else:
                helpful_msg = f"Failed to connect to {target_url}. Please verify the target is reachable. Original error: {error_msg}"

            logger.error("[!] Connection error: %s", helpful_msg)
            return PluginError(
                error_type="ConnectionError",
                message=helpful_msg,
                traceback=str(e.__traceback__),
            )
        except Exception as e:
            logger.exception("[!] Error during file upload testing: %s", e)
            return PluginError(
                error_type=type(e).__name__,
                message=str(e),
                traceback=str(e.__traceback__),
            )

        return PluginResult(
            plugin_name=self.name,
            status=PluginStatus.SUCCESS,
            findings=findings,
            start_time=start_time,
            end_time=datetime.now(),
            duration_seconds=(datetime.now() - start_time).total_seconds(),
            urls_scanned=int(stats["urls_scanned"]),
            requests_sent=stats["requests_sent"],
        )


def main(config: PluginContext | None = None):
    """플러그인 인스턴스를 생성하여 반환합니다."""
    return FileUploadPlugin(config)


# 이 파일을 직접 실행할 때 main()을 호출
if __name__ == "__main__":
    main()
