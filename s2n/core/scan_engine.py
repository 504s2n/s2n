# 실제 스캐닝 엔진 (플러그인 관리 + 실행))
"""
이 모듈은 s2n의 핵심 로직을 구현합니다.
CLI나 패키지 방식으로 호출될 수 있으며, 
DVWA Adapter 인증 -> HttpClient 공유 -> Plugin 실행 -> ScanReport 반환의 흐름을 관리합니다.
"""

from __future__ import annotations
import logging
import importlib
import pkgutil
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable

# from s2n.core.interfaces import ScanReport, Finding, PluginSpec