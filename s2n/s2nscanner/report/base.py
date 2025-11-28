# 공통 인터페이스/추상클래스

from abc import ABC, abstractmethod
from pathlib import Path
from s2n.s2nscanner.interfaces import ScanReport, OutputFormat

class ReportFormatter(ABC):
    @abstractmethod
    def format(self, report: ScanReport) -> str:
        pass

    @abstractmethod
    def save(self, report: ScanReport, path: Path):
        pass