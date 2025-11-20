"""
공통 클라이언트 프로토콜 정의 모듈

- HttpClientProtocol: requests 기반 HTTP 클라이언트가 따라야 할 공통 인터페이스
- BrowserClientProtocol: Selenium 기반 브라우저 클라이언트가 따라야 할 공통 인터페이스
- 구성용 dataclass (HttpClientConfig, BrowserClientConfig)

이 파일은 'interface 역할'만 담당
구현체는 http_client.py, browser_client.py에서 제공
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Protocol

# ----------------------------------------------------------
# HTTP Client Protocol + Config
# ----------------------------------------------------------
class HttpClientProtocol(Protocol):
    """HTTP 요청을 위한 공통 인터페이스 (requests 기반)"""

    s: Any

    def request(self, method: str, url: str, **kwargs) -> Any: ...
    def get(self, url: str, **kwargs) -> Any: ...
    def post(self, url: str, data=None, **kwargs) -> Any: ...

    def set_header(self, key: str, value: str) -> None: ...
    def set_cookie(self, key: str, value: str, domain: Optional[str]) -> None: ...

    def close(self) -> None: ...

@dataclass
class HttpClientConfig:
    retry: int = 1
    backoff: float = 0.2
    timeout: Optional[float] = None
    verify_ssl: bool = True
    base_headers: Dict[str, str] = field(default_factory=dict)
    allow_redirects: bool = True
    base_url: Optional[str] = None

# ----------------------------------------------------------
# Browser Client Protocol + Config
# ----------------------------------------------------------
class BrowserClientProtocol(Protocol):
    """Selenium WebDriver 호환 인터페이스"""

    driver: Any

    def get(self, url: str) -> None: ...
    def find(self, by: Any, value: str) -> Any: ...
    def wait(self, fn: Callable, timeout: Optional[float] = None) -> Any: ...
    def page_source(self) -> str: ...
    def quit(self) -> None: ...

    @property
    def raw(self) -> Any: ...

@dataclass
class BrowserClientConfig:
    wait_timeout: float = 15
    poll_frequency: float = 0.5

__all__ = [
    "HttpClientProtocol",
    "BrowserClientProtocol",
    "HttpClientConfig",
    "BrowserClientConfig",
]
