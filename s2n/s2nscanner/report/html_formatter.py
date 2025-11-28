# ScanReport -> HTML 변환 + 저장

from __future__ import annotations
from pathlib import Path
from typing import List

from s2n.s2nscanner.interfaces import ScanReport, Severity
from s2n.s2nscanner.report.base import ReportFormatter

class HTMLFormatter(ReportFormatter):
    def __init__(self):
        pass

    def format(self, report: ScanReport) -> str:
        html_parts: List[str] = []

        html_parts.append(
        """<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>S2N Scanner Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary { background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .summary-item { margin: 10px 0; }
        .severity-critical { color: #d32f2f; font-weight: bold; }
        .severity-high { color: #f57c00; font-weight: bold; }
        .severity-medium { color: #fbc02d; }
        .severity-low { color: #388e3c; }
        .severity-info { color: #1976d2; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #4CAF50; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .finding { margin: 20px 0; padding: 15px; border-left: 4px solid #4CAF50; background: #fafafa; }
        .metadata { font-size: 0.9em; color: #666; }
    </style>
</head>
<body>
    <div class="container">"""
    )

        # 제목
        html_parts.append(f"<h1>S2N Scanner Report</h1>")

        # 기본 정보
        html_parts.append("<div class='summary'>")
        html_parts.append(
            f"<div class='summary-item'><strong>Target URL:</strong> {report.target_url}</div>"
        )
        html_parts.append(
            f"<div class='summary-item'><strong>Scan ID:</strong> {report.scan_id}</div>"
        )
        html_parts.append(
            f"<div class='summary-item'><strong>Scanner Version:</strong> {report.scanner_version}</div>"
        )
        html_parts.append(
            f"<div class='summary-item'><strong>Start Time:</strong> {report.start_time.isoformat()}</div>"
        )
        html_parts.append(
            f"<div class='summary-item'><strong>End Time:</strong> {report.end_time.isoformat()}</div>"
        )
        html_parts.append(
            f"<div class='summary-item'><strong>Duration:</strong> {report.duration_seconds:.2f} seconds</div>"
        )
        html_parts.append("</div>")

        # 요약 정보
        if report.summary:
            summary = report.summary
            html_parts.append("<h2>Summary</h2>")
            html_parts.append("<div class='summary'>")
            html_parts.append(
                f"<div class='summary-item'><strong>Total Vulnerabilities:</strong> {summary.total_vulnerabilities}</div>"
            )
            html_parts.append(
                f"<div class='summary-item'><strong>Total URLs Scanned:</strong> {summary.total_urls_scanned}</div>"
            )
            html_parts.append(
                f"<div class='summary-item'><strong>Total Requests:</strong> {summary.total_requests}</div>"
            )
            html_parts.append(
                f"<div class='summary-item'><strong>Success Rate:</strong> {summary.success_rate:.1f}%</div>"
            )

            if summary.severity_counts:
                html_parts.append(
                    "<div class='summary-item'><strong>Severity Breakdown:</strong></div>"
                )
                html_parts.append("<ul>")
                for severity in [
                    Severity.CRITICAL,
                    Severity.HIGH,
                    Severity.MEDIUM,
                    Severity.LOW,
                    Severity.INFO,
                ]:
                    count = summary.severity_counts.get(severity, 0)
                    if count > 0:
                        severity_class = f"severity-{severity.value.lower()}"
                        html_parts.append(
                            f"<li class='{severity_class}'>{severity.value}: {count}</li>"
                        )
                html_parts.append("</ul>")
            html_parts.append("</div>")

        # Finding 상세 정보
        html_parts.append("<h2>Findings</h2>")

        for plugin_result in report.plugin_results:
            if plugin_result.findings:
                html_parts.append(f"<h3>Plugin: {plugin_result.plugin_name}</h3>")
                html_parts.append(
                    f"<p><strong>Status:</strong> {plugin_result.status.value}</p>"
                )
                html_parts.append(
                    f"<p><strong>Findings Count:</strong> {len(plugin_result.findings)}</p>"
                )

                for finding in plugin_result.findings:
                    severity_class = f"severity-{finding.severity.value.lower()}"
                    html_parts.append(f"<div class='finding'>")
                    html_parts.append(
                        f"<h4 class='{severity_class}'>[{finding.severity.value}] {finding.title}</h4>"
                    )
                    html_parts.append(f"<p><strong>ID:</strong> {finding.id}</p>")
                    if finding.url:
                        html_parts.append(f"<p><strong>URL:</strong> {finding.url}</p>")
                    if finding.parameter:
                        html_parts.append(
                            f"<p><strong>Parameter:</strong> {finding.parameter}</p>"
                        )
                    if finding.method:
                        html_parts.append(
                            f"<p><strong>Method:</strong> {finding.method}</p>"
                        )
                    if finding.payload:
                        html_parts.append(
                            f"<p><strong>Payload:</strong> <code>{finding.payload}</code></p>"
                        )
                    if finding.description:
                        html_parts.append(
                            f"<p><strong>Description:</strong> {finding.description}</p>"
                        )
                    if finding.evidence:
                        html_parts.append(
                            f"<p><strong>Evidence:</strong> {finding.evidence}</p>"
                        )
                    if finding.remediation:
                        html_parts.append(
                            f"<p><strong>Remediation:</strong> {finding.remediation}</p>"
                        )
                    if finding.cwe_id:
                        html_parts.append(
                            f"<p><strong>CWE ID:</strong> {finding.cwe_id}</p>"
                        )
                    if finding.cvss_score:
                        html_parts.append(
                            f"<p><strong>CVSS Score:</strong> {finding.cvss_score}</p>"
                        )
                    html_parts.append(
                        f"<p class='metadata'><strong>Confidence:</strong> {finding.confidence.value} | <strong>Timestamp:</strong> {finding.timestamp.isoformat()}</p>"
                    )
                    html_parts.append("</div>")

        # HTML 푸터
        html_parts.append(
            """
        </div>
    </body>
    </html>"""
        )

        return "\n".join(html_parts)
    

    def save(self, report: ScanReport, path: Path):
        html_str = self.format(report)
        path = Path(path)
        path.write_text(html_str, encoding="utf-8")