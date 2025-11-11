"""
Report 출력 모듈

ScanReport를 다양한 형식(JSON, HTML, CSV, CONSOLE)으로 변환하고 출력하는 함수들을 제공합니다.
"""

import csv
import json
import traceback
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

from s2n.s2nscanner.interfaces import (
    ScanReport,
    OutputFormat,
    OutputConfig,
    ConsoleOutput,
    ConsoleMode,
    JSONOutput,
    Severity,
)


def _serialize_datetime(obj: Any) -> str:
    """datetime 객체를 ISO8601 형식 문자열로 변환"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def _scan_report_to_dict(report: ScanReport) -> Dict[str, Any]:
    """ScanReport를 딕셔너리로 변환 (datetime은 ISO 형식으로)"""
    return json.loads(json.dumps(asdict(report), default=_serialize_datetime))


def format_report_to_json(report: ScanReport, pretty_print: bool = True) -> JSONOutput:
    """
    ScanReport를 JSON 문자열로 변환합니다.

    Args:
        report: 변환할 스캔 리포트
        pretty_print: JSON을 보기 좋게 포맷팅할지 여부

    Returns:
        str: JSON 형식의 문자열
    """
    report_dict = _scan_report_to_dict(report)

    if pretty_print:
        return json.dumps(
            report_dict, indent=2, ensure_ascii=False, default=_serialize_datetime
        )
    else:
        return json.dumps(report_dict, ensure_ascii=False, default=_serialize_datetime)


def format_report_to_console(
        report: ScanReport, mode: ConsoleMode = ConsoleMode.SUMMARY
) -> ConsoleOutput:
    """
    ScanReport를 ConsoleOutput으로 변환합니다.

    Args:
        report: 변환할 스캔 리포트
        mode: 콘솔 출력 모드

    Returns:
        ConsoleOutput: 콘솔 출력 데이터
    """
    summary_lines: List[str] = []
    detail_lines: List[str] = []

    # 기본 요약 정보
    if report.summary:
        summary = report.summary
        summary_lines.append("=" * 60)
        summary_lines.append("Scan Report Summary")
        summary_lines.append("=" * 60)
        summary_lines.append(f"Target URL: {report.target_url}")
        summary_lines.append(f"Scan ID: {report.scan_id}")
        summary_lines.append(f"Scanner Version: {report.scanner_version}")
        summary_lines.append(f"Duration: {report.duration_seconds:.2f} seconds")
        summary_lines.append("")
        summary_lines.append(f"Total Vulnerabilities: {summary.total_vulnerabilities}")
        summary_lines.append(f"Total URLs Scanned: {summary.total_urls_scanned}")
        summary_lines.append(f"Total Requests: {summary.total_requests}")
        summary_lines.append(f"Success Rate: {summary.success_rate:.1f}%")
        summary_lines.append("")

        # 심각도별 카운트
        if summary.severity_counts:
            summary_lines.append("Severity Breakdown:")
            for severity in [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            ]:
                count = summary.severity_counts.get(severity, 0)
                if count > 0:
                    summary_lines.append(f"  {severity.value}: {count}")

        # 플러그인별 카운트
        if summary.plugin_counts:
            summary_lines.append("")
            summary_lines.append("Plugin Breakdown:")
            for plugin_name, count in summary.plugin_counts.items():
                summary_lines.append(f"  {plugin_name}: {count}")

    # 상세 정보 (VERBOSE 또는 DEBUG 모드)
    if mode in [ConsoleMode.VERBOSE, ConsoleMode.DEBUG]:
        detail_lines.append("")
        detail_lines.append("=" * 60)
        detail_lines.append("Detailed Findings")
        detail_lines.append("=" * 60)

        for plugin_result in report.plugin_results:
            if plugin_result.findings:
                detail_lines.append("")
                detail_lines.append(f"Plugin: {plugin_result.plugin_name}")
                detail_lines.append(f"Status: {plugin_result.status.value}")
                detail_lines.append(f"Findings: {len(plugin_result.findings)}")
                detail_lines.append("-" * 60)

                for finding in plugin_result.findings:
                    detail_lines.append(f"  [{finding.severity.value}] {finding.title}")
                    if finding.url:
                        detail_lines.append(f"    URL: {finding.url}")
                    if finding.parameter:
                        detail_lines.append(f"    Parameter: {finding.parameter}")
                    if finding.payload:
                        detail_lines.append(f"    Payload: {finding.payload}")
                    if finding.description:
                        detail_lines.append(f"    Description: {finding.description}")
                    detail_lines.append("")

    return ConsoleOutput(
        mode=mode,
        summary_lines=summary_lines,
        detail_lines=detail_lines,
    )


def format_report_to_csv(report: ScanReport) -> str:
    """
    ScanReport를 CSV 문자열로 변환합니다.

    Args:
        report: 변환할 스캔 리포트

    Returns:
        str: CSV 형식의 문자열
    """
    import io

    output = io.StringIO()
    writer = csv.writer(output)

    # 헤더
    writer.writerow(
        [
            "ID",
            "Plugin",
            "Severity",
            "Title",
            "URL",
            "Parameter",
            "Method",
            "Payload",
            "Evidence",
            "CWE ID",
            "CVSS Score",
            "Confidence",
            "Timestamp",
        ]
    )

    # Finding 데이터
    for plugin_result in report.plugin_results:
        for finding in plugin_result.findings:
            writer.writerow(
                [
                    finding.id,
                    finding.plugin,
                    finding.severity.value,
                    finding.title,
                    finding.url or "",
                    finding.parameter or "",
                    finding.method or "",
                    finding.payload or "",
                    finding.evidence or "",
                    finding.cwe_id or "",
                    finding.cvss_score or "",
                    finding.confidence.value,
                    finding.timestamp.isoformat() if finding.timestamp else "",
                ]
            )

    return output.getvalue()


def format_report_to_html(report: ScanReport) -> str:
    """
    ScanReport를 HTML 문자열로 변환합니다.

    Args:
        report: 변환할 스캔 리포트

    Returns:
        str: HTML 형식의 문자열
    """
    html_parts = []

    # HTML 헤더
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


def save_report(
        report: ScanReport,
        output_path: Path,
        output_format: OutputFormat = OutputFormat.JSON,
        pretty_print: bool = True,
) -> None:
    """
    ScanReport를 지정된 형식으로 파일에 저장합니다.

    Args:
        report: 저장할 스캔 리포트
        output_path: 출력 파일 경로
        output_format: 출력 형식
        pretty_print: JSON의 경우 보기 좋게 포맷팅할지 여부
    """
    output_path = Path(output_path)

    if output_format == OutputFormat.JSON:
        content = format_report_to_json(report, pretty_print=pretty_print)
        output_path.write_text(content, encoding="utf-8")

    elif output_format == OutputFormat.HTML:
        content = format_report_to_html(report)
        output_path.write_text(content, encoding="utf-8")

    elif output_format == OutputFormat.CSV:
        content = format_report_to_csv(report)
        output_path.write_text(content, encoding="utf-8")

    else:
        raise ValueError(f"Unsupported output format: {output_format}")


def output_report(report: ScanReport, config: OutputConfig) -> None:
    """
    OutputConfig에 따라 ScanReport를 출력합니다.

    Args:
        report: 출력할 스캔 리포트
        config: 출력 설정
    """
    if config.format == OutputFormat.CONSOLE:
        console_output = format_report_to_console(report, mode=config.console_mode)
        for line in console_output.summary_lines:
            print(line)
        for line in console_output.detail_lines:
            print(line)

    elif config.format == OutputFormat.JSON:
        json_str = format_report_to_json(report, pretty_print=config.pretty_print)
        if config.path:
            Path(config.path).write_text(json_str, encoding="utf-8")
        else:
            print(json_str)

    elif config.format == OutputFormat.HTML:
        if not config.path:
            raise ValueError("HTML output requires output path")
        html_str = format_report_to_html(report)
        Path(config.path).write_text(html_str, encoding="utf-8")

    elif config.format == OutputFormat.CSV:
        if not config.path:
            raise ValueError("CSV output requires output path")
        csv_str = format_report_to_csv(report)
        Path(config.path).write_text(csv_str, encoding="utf-8")

    elif config.format == OutputFormat.MULTI:
        # 여러 형식으로 동시 출력
        base_path = config.path or Path("report")
    try:
        # JSON
        json_path = base_path.with_suffix(".json")
        save_report(report, json_path, OutputFormat.JSON, config.pretty_print)

        # HTML
        html_path = base_path.with_suffix(".html")
        save_report(report, html_path, OutputFormat.HTML)

        # CSV
        csv_path = base_path.with_suffix(".csv")
        save_report(report, csv_path, OutputFormat.CSV)

        # CONSOLE
        console_output = format_report_to_console(report, mode=config.console_mode)
        for line in console_output.summary_lines:
            print(line)
        for line in console_output.detail_lines:
            print(line)
    except Exception as ex:
        traceback.print_exc()
        print(f"[ERROR]: REPORT FAILED: {ex} (MULTI Option error)")
    else:
        raise ValueError(f"Unsupported output format: {config.format}")
