"""
s2n.s2nscanner.clients 패키지 공개 API 

- HttpCleint / BrowserClient를 기본 구현체로 export
- Protocol 및 Config도 함께 export
"""

from .protocols import (
    HttpClientProtocol,
    BrowserClientProtocol,
    HttpClientConfig,
    BrowserClientConfig,
)

from .http_client import (
    RequestsHttpClient,
    HttpClient,
)

from .browser_client import (
    SeleniumBrowserClient,
    BrowserClient,
)

__all__ = [
    # protocols
    "HttpClientProtocol",
    "BrowserClientProtocol",

    # config
    "HttpClientConfig",
    "BrowserClientConfig",

    # http client
    "RequestsHttpClient",
    "HttpClient",

    # browser client
    "SeleniumBrowserClient",
    "BrowserClient",
]