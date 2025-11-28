# 멀티 출력 핸들러

"""
Multi Formatter Module

여러 출력 포맷(JSON, HTML, CSV, Console)을 동시에 생성하는 Formatter입니다.
config.path의 파일명을 기준으로 확장자를 변경하여
*.json, *.html, *.csv 파일을 자동으로 생성합니다.
"""

from __future__ import annotations
from pathlib import Path
from typing import Optional

from s2n.s2nscanner.interfaces import (
    ScanReport,
    ConsoleMode,
)
from s2n.s2nscanner.report.base import ReportFormatter
from s2n.s2nscanner.report.json_formatter import JSONFormatter
from s2n.s2nscanner.report.html_formatter import HTMLFormatter
from s2n.s2nscanner.report.csv_formatter import CSVFormatter
from s2n.s2nscanner.report.console_formatter import ConsoleFormatter


class MultiFormatter(ReportFormatter):
    """
    MULTI 출력 모드 Formatter

    - JSON, HTML, CSV 파일을 모두 생성
    - Console 모드는 문자열로 반환
    """

    def __init__(
        self,
        pretty_print: bool = True,
        console_mode: ConsoleMode = ConsoleMode.SUMMARY,
    ):
        self.json_formatter = JSONFormatter(pretty_print=pretty_print)
        self.html_formatter = HTMLFormatter()
        self.csv_formatter = CSVFormatter()
        self.console_formatter = ConsoleFormatter(mode=console_mode)

    def _build_output_paths(self, base_path: Optional[Path]) -> dict:
        """
        base_path가 'report' 이면:
            report.json
            report.html
            report.csv
        를 자동 생성하는 구조.
        """
        if base_path is None:
            base_path = Path("report")

        base_path = Path(base_path)

        return {
            "json": base_path.with_suffix(".json"),
            "html": base_path.with_suffix(".html"),
            "csv": base_path.with_suffix(".csv"),
        }

    # ------------------------------------------------------------------
    # format()
    # MULTI의 경우 format()은 콘솔 내용만 문자열로 반환
    # (파일 출력은 save()에서 처리)
    # ------------------------------------------------------------------
    def format(self, report: ScanReport) -> str:
        """MULTI 모드에서 콘솔 출력 문자열만 반환"""
        return self.console_formatter.format(report)

    # ------------------------------------------------------------------
    # save()
    # JSON, HTML, CSV는 파일로 저장하고 Console은 화면용 문자열만 반환
    # ------------------------------------------------------------------
    def save(self, report: ScanReport, path: Path):
        """
        MULTI 모드 저장:
        - base_path.json
        - base_path.html
        - base_path.csv
        를 자동 생성.
        """
        output_paths = self._build_output_paths(path)

        # JSON 저장
        self.json_formatter.save(report, output_paths["json"])

        # HTML 저장
        self.html_formatter.save(report, output_paths["html"])

        # CSV 저장
        self.csv_formatter.save(report, output_paths["csv"])

        # Console 내용 반환 (저장X)
        console_text = self.console_formatter.format(report)

        # 사용자가 원하면 파일로 저장할 수도 있지만,
        # 일반적으로 Console은 화면 출력용이라 save()에서는 저장하지 않음.

        return console_text