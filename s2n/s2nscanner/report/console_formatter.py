# 콘솔 데이터 구성

"""
Console Formatter Module

ScanReport 객체를 콘솔 출력용 문자열로 변환하는 기능을 제공합니다.
파일 저장은 하지 않으며, format()은 출력 문자열을 반환합니다.
"""

from __future__ import annotations
from pathlib import Path
from typing import List

from s2n.s2nscanner.interfaces import (
    ScanReport,
    Severity,
    ConsoleMode,
    ConsoleOutput,
)
from s2n.s2nscanner.report.base import ReportFormatter


class ConsoleFormatter(ReportFormatter):
    """
    Console 형식 Formatter

    기능:
    - ScanReport → 콘솔 요약/상세 문자열 생성
    - save()는 no-op 처리 (혹은 파일 저장 지원 가능하지만 일반적으로 필요 없음)
    """

    def __init__(self, mode: ConsoleMode = ConsoleMode.SUMMARY):
        self.mode = mode

    def format(self, report: ScanReport) -> str:
        """ScanReport를 사람이 읽기 좋은 콘솔 출력 문자열로 변환"""

        summary_lines: List[str] = []
        detail_lines: List[str] = []

        # Summary Header
        summary_lines.append("=" * 60)
        summary_lines.append("Scan Report Summary")
        summary_lines.append("=" * 60)
        summary_lines.append(f"Target URL: {report.target_url}")
        summary_lines.append(f"Scan ID: {report.scan_id}")
        summary_lines.append(f"Scanner Version: {report.scanner_version}")
        summary_lines.append(f"Duration: {report.duration_seconds:.2f} seconds")
        summary_lines.append("")

        # Summary Data
        if report.summary:
            s = report.summary
            summary_lines.append(f"Total Vulnerabilities: {s.total_vulnerabilities}")
            summary_lines.append(f"Total URLs Scanned: {s.total_urls_scanned}")
            summary_lines.append(f"Total Requests: {s.total_requests}")
            summary_lines.append(f"Success Rate: {s.success_rate:.1f}%")
            summary_lines.append("")

            # Severity Breakdown
            if s.severity_counts:
                summary_lines.append("Severity Breakdown:")
                for sev in [
                    Severity.CRITICAL,
                    Severity.HIGH,
                    Severity.MEDIUM,
                    Severity.LOW,
                    Severity.INFO,
                ]:
                    cnt = s.severity_counts.get(sev, 0)
                    if cnt > 0:
                        summary_lines.append(f"  {sev.value}: {cnt}")

            # Plugin Breakdown
            if s.plugin_counts:
                summary_lines.append("")
                summary_lines.append("Plugin Breakdown:")
                for plugin_name, count in s.plugin_counts.items():
                    summary_lines.append(f"  {plugin_name}: {count}")

        # Detailed Section
        if self.mode in [ConsoleMode.VERBOSE, ConsoleMode.DEBUG]:
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

                    for f in plugin_result.findings:
                        detail_lines.append(f"  [{f.severity.value}] {f.title}")
                        if f.url:
                            detail_lines.append(f"    URL: {f.url}")
                        if f.parameter:
                            detail_lines.append(f"    Parameter: {f.parameter}")
                        if f.method:
                            detail_lines.append(f"    Method: {f.method}")
                        if f.payload:
                            detail_lines.append(f"    Payload: {f.payload}")
                        if f.description:
                            detail_lines.append(f"    Description: {f.description}")
                        detail_lines.append("")

        output = ConsoleOutput(
            mode=self.mode,
            summary_lines=summary_lines,
            detail_lines=detail_lines,
        )

        # format()은 문자열 반환이므로 join 처리
        return "\n".join(output.summary_lines + output.detail_lines)

    def save(self, report: ScanReport, path: Path):
        # no-op
        pass

