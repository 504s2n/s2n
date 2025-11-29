from datetime import datetime
from typing import List, Dict, Any, Optional

from s2n.s2nscanner.interfaces import (
    Finding,
    PluginContext,
    PluginError,
    PluginResult,
    PluginStatus,
)
from s2n.s2nscanner.logger import get_logger
from s2n.s2nscanner.plugins.sqlinjection.sqli_scan import sqli_scan
from s2n.s2nscanner.plugins.helper import resolve_client, resolve_depth, resolve_target_url

logger = get_logger("plugins.sqlinjection")


class SQLInjectionPlugin:
    name = "sqlinjection"
    description = "SQL Injection 취약점을 스캐너"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.timeout = int(self.config.get("timeout", 5))
        self.depth = int(self.config.get("depth", 2))

    def run(self, plugin_context: PluginContext) -> PluginResult:
        start_dt = datetime.now()
        findings: List[Finding] = []

        # Extract configuration from plugin context
        client = resolve_client(self, plugin_context)
        depth = resolve_depth(self, plugin_context)
        target_url = resolve_target_url(self, plugin_context)

        try:
            # Scan for SQL injection vulnerabilities (crawler integrated in sqli_scan)
            scan_result = sqli_scan(
                target_url,
                http_client=client,
                plugin_context=plugin_context,
                depth=depth,
                timeout=self.timeout,
            )
            findings.extend(scan_result)

        except Exception as e:
            logger.exception(f"[SQLInjectionPlugin.run] plugin error: {e}")
            return PluginResult(
                plugin_name=self.name,
                status=PluginStatus.FAILED,
                error=PluginError(
                    error_type=type(e).__name__,
                    message=str(e),
                    traceback=str(e.__traceback__),
                ),
                duration_seconds=(datetime.now() - start_dt).total_seconds(),
            )

        # Determine status based on findings
        status = PluginStatus.PARTIAL if findings else PluginStatus.SUCCESS

        return PluginResult(
            plugin_name=self.name,
            status=status,
            findings=findings,
            duration_seconds=(datetime.now() - start_dt).total_seconds(),
            requests_sent=0,  # TODO: Track requests count if needed
        )


def main(config=None):
    return SQLInjectionPlugin(config)
