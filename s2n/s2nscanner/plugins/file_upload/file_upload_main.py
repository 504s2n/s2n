from typing import List
from datetime import datetime

# interfaces에서 제공되는 타입 사용
from s2n.s2nscanner.interfaces import (
    Finding,
    PluginContext,
    PluginError,
    PluginResult,
    PluginStatus,
)
from s2n.s2nscanner.logger import get_logger
from s2n.s2nscanner.crawler import crawl_recursive

# 헬퍼 함수 임포트
try:
    from .file_upload_utils import (
        collect_form_data,
        authenticate_if_needed,
        find_upload_form,
        upload_test_files,
    )
except ImportError:
    from file_upload_utils import (
        collect_form_data,
        authenticate_if_needed,
        find_upload_form,
        upload_test_files,
    )

logger = get_logger("plugins.file_upload")


class FileUploadPlugin:
    name = "file_upload"
    description = "파일 업로드 취약점을 탐지합니다."

    def __init__(self, config: PluginContext | None = None):
        self.config = config or {}
        # depth: config에서 가져오거나 기본값 2 사용
        self.depth = int(getattr(self.config, "depth", 2))

    def run(self, plugin_context: PluginContext) -> PluginResult | PluginError:
        start_time = datetime.now()
        findings: List[Finding] = []
        stats = {"requests_sent": 0, "urls_scanned": 0}
        target_url = plugin_context.scan_context.config.target_url
        http_client = plugin_context.scan_context.http_client
        
        # depth 옵션 추출 (plugin_config에서 우선, 없으면 인스턴스 기본값)
        depth = self.depth
        plugin_cfg = getattr(plugin_context, "plugin_config", None)
        if plugin_cfg and getattr(plugin_cfg, "custom_params", None):
            depth = int(plugin_cfg.custom_params.get("depth", depth))

        try:
            logger.info("[*] Starting file upload scan on: %s (depth=%d)", target_url, depth)
            
            # 1. Initial request and authentication
            resp = http_client.get(target_url, timeout=10)
            stats["requests_sent"] += 1
            stats["urls_scanned"] += 1
            resp = authenticate_if_needed(plugin_context, resp, http_client, stats)

            # 2. Crawl to discover URLs
            crawled_urls = crawl_recursive(target_url, http_client, depth=depth, timeout=10)
            logger.info("[*] Discovered %d URLs to scan for upload forms", len(crawled_urls))
            
            # 3. Search for upload forms across discovered URLs
            for url in crawled_urls:
                try:
                    logger.info("[*] Checking for upload form at: %s", url)
                    page_resp = http_client.get(url, timeout=10)
                    stats["requests_sent"] += 1
                    stats["urls_scanned"] += 1
                    
                    form = find_upload_form(page_resp.text)
                    if not form:
                        continue
                    
                    logger.info("[+] Found upload form at: %s", url)
                    
                    # Prepare upload parameters
                    action = form.get("action") or url
                    from urllib.parse import urljoin
                    action_url = urljoin(url, action)
                    method = str(form.get("method", "post")).lower()
                    
                    if method != "post":
                        logger.warning("Form method is not POST (method=%s). Skipping.", method)
                        continue
                    
                    data = collect_form_data(form)
                    file_input = next((i for i in form.inputs if i.get("type") == "file"), None)
                    if not file_input:
                        logger.info("No file input found in form. Skipping.")
                        continue
                    
                    file_field_name = str(file_input.get("name", "file"))
                    
                    # Execute upload tests
                    logger.info("[*] Testing file upload at: %s", action_url)
                    new_findings = upload_test_files(
                        http_client, action_url, data, file_field_name, self.name, stats
                    )
                    findings.extend(new_findings)
                    
                except Exception as e:
                    logger.warning("Error scanning URL %s: %s", url, e)
                    continue

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
