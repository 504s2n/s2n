from typing import List
from datetime import datetime
from s2n.s2nscanner.plugins.csrf.csrf_constants import USER_AGENT

import requests
from urllib.parse import urljoin

# interfaces에서 제공되는 타입 사용
from s2n.s2nscanner.interfaces import (
    Finding,
    PluginContext,
    PluginError,
    PluginResult,
    PluginStatus,
)
from s2n.s2nscanner.logger import get_logger

# 헬퍼 함수 임포트
try:
    from .file_upload_utils import (
        collect_form_data,
        authenticate_if_needed,
        find_upload_form_recursive,
        upload_test_files,
    )
except ImportError:
    from file_upload_utils import (
        collect_form_data,
        authenticate_if_needed,
        find_upload_form_recursive,
        upload_test_files,
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

            # 1. Authenticate if needed (updates stats internally if requests made)
            resp = authenticate_if_needed(plugin_context, resp, http_client, stats)

            # 2. Find upload form (recursive)
            form, found_at = find_upload_form_recursive(
                target_url, http_client, plugin_context, resp, stats
            )

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

            # 3. Prepare for upload
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

            # 4. Execute upload tests
            new_findings = upload_test_files(
                http_client, action_url, data, file_field_name, self.name, stats
            )
            findings.extend(new_findings)

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
