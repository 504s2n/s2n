# 플러그인 표준에 따라 __init__.py 파일을 생성합니다.
# sqli_main.py 파일 내의 SQLInjectionPlugin 클래스를 임포트합니다.
from .sqli_main import SQLInjectionPlugin

__all__ = ["SQLInjectionPlugin"]