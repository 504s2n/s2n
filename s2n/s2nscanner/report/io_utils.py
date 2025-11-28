# 파일 저장 공통 유틸

"""
I/O Utility Module

Formatter들이 공통적으로 사용하는 파일 저장 유틸리티를 제공합니다.
Path 생성, 디렉토리 생성, 안전한 파일 쓰기 등을 담당합니다.
"""

from __future__ import annotations
from pathlib import Path


def ensure_parent(path: Path) -> None:
    """
    파일 경로의 부모 디렉토리가 존재하지 않으면 생성합니다.
    """
    parent = path.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)


def write_text_file(path: Path, content: str, encoding: str = "utf-8") -> None:
    """
    텍스트 파일을 안전하게 저장합니다.

    Args:
        path: 저장할 파일 경로
        content: 파일에 기록할 텍스트 내용
        encoding: 파일 인코딩 (기본 utf-8)
    """
    path = Path(path)
    ensure_parent(path)
    path.write_text(content, encoding=encoding)


def write_binary_file(path: Path, data: bytes) -> None:
    """
    바이너리 파일을 안전하게 저장합니다.
    HTML / JSON / CSV는 바이너리가 아니지만,
    향후 PDF 등 지원 시 사용 가능하도록 제공.

    Args:
        path: 저장할 파일 경로
        data: 바이트 데이터
    """
    path = Path(path)
    ensure_parent(path)
    path.write_bytes(data)


def safe_write(path: Path, content: str | bytes, encoding: str = "utf-8") -> None:
    """
    텍스트/바이너리 모두 지원하는 통합 API.

    Args:
        path: 저장 경로
        content: 문자열 또는 bytes
        encoding: 문자열일 경우 인코딩 지정
    """
    if isinstance(content, bytes):
        write_binary_file(path, content)
    else:
        write_text_file(path, content, encoding=encoding)