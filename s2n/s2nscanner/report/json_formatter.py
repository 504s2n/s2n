# Json 변환 + 저장

from __future__ import annotations
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict
from s2n.s2nscanner.interfaces import ScanReport
from s2n.s2nscanner.report.base import ReportFormatter

def _serialize_datetime(obj: Any) -> str:
    """datetime 객체를 ISO8601 형식 문자열로 변환 : datetime 전용 직렬화 함수"""
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)

def _scan_report_to_dict(report: ScanReport) -> Dict[str, Any]:
    """ScanReport를 딕셔너리로 변환 (datetime은 ISO 형식으로)"""
    return json.loads(json.dumps(asdict(report), default=_serialize_datetime))

class JSONFormatter(ReportFormatter):
    def __init__(self, pretty_print: bool = True):
        self.pretty_print = pretty_print

    def format(self, report: ScanReport) -> str:
        report_dict = _scan_report_to_dict(report)
        if self.pretty_print:
            return json.dumps(
                report_dict,
                ensure_ascii=False, 
                indent=2,
                default=_serialize_datetime,
            )
        
        return json.dumps(
            report_dict,
            ensure_ascii=False,
            default=_serialize_datetime,
        )

    def save(self, report: ScanReport, path: Path):
        json_str = self.format(report)
        path = Path(path)
        path.write_text(json_str, encoding="utf-8")
        