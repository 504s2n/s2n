"""
HTTP Client (requests 기반)
- requests.Session을 래핑해서 재시도/백오프/타임아웃/SSL 검증/헤더 일원화
- 모든 플러그인은 HttpClientProtocol 인터페이스를 구현해야 함
"""

from __future__ import annotations

import time
from typing import Optional

import requests
from requests import Response, Session, RequestException

from .protocols import HttpClientProtocol, HttpClientConfig


# requests 기반 구현
class RequestsHttpClient(HttpClientProtocol):
    """
    requests.Session 래퍼. 
    - 모든 HTTP 요청을 중앙에서 통제
    - backoff, timeout, SSL, header, session 재사용 통일
    """

    def __init__(
        self,
        config: Optional[HttpClientConfig] = None,
        session: Optional[Session] = None,
    ):
        self.config = config or HttpClientConfig()
        self.s = session or requests.Session()
        
        if self.config.base_headers:
            self.s.headers.update(self.config.base_headers)

        # HTTP 로그 훅 (엔진에서 주입)
        self.log_hook = None

    # 내부: 재시도 래퍼
    def _send_with_retry(self, method: str, url: str, **kwargs) -> Response:
        retry = self.config.retry
        backoff = self.config.backoff

        # base_url 지원 (선택)
        if self.config.base_url and not url.startswith("http"):
            url = self.config.base_url.rstrip("/") + "/" + url.lstrip("/")

        for attempt in range(retry + 1):
            try:
                merged_kwargs = dict(
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl,
                    allow_redirects=self.config.allow_redirects,
                    **kwargs,
                )

                res = self.s.request(method=method, url=url, **merged_kwargs)

                if self.log_hook:
                    self.log_hook(method, url, merged_kwargs, res)

                return res

            except RequestException:
                if attempt >= retry:
                    raise
                time.sleep(backoff * (2**attempt))

        raise RuntimeError("HTTP request failed unexpectedly")  # 미도달 보호
    
    # Public API
    def request(self, method: str, url: str, **kwargs) -> Response:
        return self._send_with_retry(method, url, **kwargs)

    def get(self, url: str, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, data=None, **kwargs) -> Response:
        return self.request("POST", url, data=data, **kwargs)
    
    # 편의 method (dvwa adapter 등에서 자주 사용)
    def set_header(self, key: str, value: str) -> None:
        self.s.headers[key] = value

    def set_cookie(self, key: str, value: str, domain: Optional[str] = None) -> None:
        self.s.cookies.set(key, value, domain=domain)

    # Context Manager
    def close(self) -> None:
        self.s.close()

    def __enter__(self) -> "RequestsHttpClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

# 과거 이름 호환
HttpClient = RequestsHttpClient

__all__ = [
    "HttpClientConfig",
    "RequestsHttpClient",
    "HttpClient",
]
