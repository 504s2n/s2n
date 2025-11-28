"""
S2N Scanner Report Package

이 패키지는 ScanReport 데이터를 다양한 출력 포맷(JSON, HTML, CSV, Console)
으로 직렬화하고 저장하는 기능을 제공합니다.

Formatter 아키텍처는 다음 원칙을 따릅니다:
- 단일 책임 원칙(SRP)
- 공통 인터페이스(ReportFormatter)
- 독립적이고 테스트 가능한 Formatter 모듈 구조
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict

from s2n.s2nscanner.interfaces import (
    ScanReport,
    OutputFormat,
    OutputConfig,
)

# Import Formatter Classes
from .base import ReportFormatter
from .json_formatter import JSONFormatter
from .html_formatter import HTMLFormatter
from .csv_formatter import CSVFormatter
from .console_formatter import ConsoleFormatter
from .multi_formatter import MultiFormatter


# ============================================================
# Formatter Routing Table
# ============================================================

FORMATTER_MAP: Dict[OutputFormat, type[ReportFormatter]] = {
    OutputFormat.JSON: JSONFormatter,
    OutputFormat.HTML: HTMLFormatter,
    OutputFormat.CSV: CSVFormatter,
    OutputFormat.CONSOLE: ConsoleFormatter,
    OutputFormat.MULTI: MultiFormatter,
}


# ============================================================
# Unified Output Function (public API)
# ============================================================

def output_report(report: ScanReport, config: OutputConfig) -> None:
    """
    OutputConfig에 따라 올바른 Formatter를 선택하여 출력하거나 파일 저장을 수행합니다.

    Args:
        report: ScanReport 객체
        config: 출력 설정 (format, path, pretty_print, console_mode 포함)
    """

    formatter_cls = FORMATTER_MAP[config.format]
    formatter = formatter_cls()

    # JSON/CONSOLE 등은 옵션별 customization 필요
    if isinstance(formatter, JSONFormatter):
        formatter.pretty_print = config.pretty_print

    if isinstance(formatter, ConsoleFormatter):
        formatter.mode = config.console_mode

    if isinstance(formatter, MultiFormatter):
        formatter.json_formatter.pretty_print = config.pretty_print
        formatter.console_formatter.mode = config.console_mode

    # 파일 저장 또는 콘솔 출력
    if config.path:
        result = formatter.save(report, Path(config.path))
        if result:   # MultiFormatter는 콘솔 문자열을 반환할 수 있음
            print(result)
    else:
        print(formatter.format(report))


# ============================================================
# Public Exports
# ============================================================

__all__ = [
    "ReportFormatter",
    "JSONFormatter",
    "HTMLFormatter",
    "CSVFormatter",
    "ConsoleFormatter",
    "MultiFormatter",
    "FORMATTER_MAP",
    "output_report",
]
