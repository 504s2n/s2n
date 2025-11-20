"""
Browser Client (Selenium 기반)

- WebDriver 래핑 -> 공통 인터페이스 제공
- 모든 플러그인은 BrowserClientProtocol 인터페이스를 구현해야 함
- wait(), find(), page_source 등 최소 기능만 노출하여 엔진 중심 구조 유지
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from .protocols import BrowserClientProtocol, BrowserClientConfig

# selenium이 설치되지 않은 환경 고려
try:
    from selenium.webdriver.remote.webdriver import WebDriver
    from selenium.webdriver.support.ui import WebDriverWait
except Exception:
    WebDriver = None  # type: ignore
    WebDriverWait = None  # type: ignore

# ----------------------------------------------------------
# selenium 기반 구현체
# ----------------------------------------------------------

class SeleniumBrowserClient(BrowserClientProtocol):
    """WebDriver를 래핑해 공통 인터페이스를 제공."""

    def __init__(self, driver: Any, config: Optional[BrowserClientConfig] = None):
        if WebDriver is None:
            raise ImportError("selenium 패키지가 필요합니다.")
        
        if not isinstance(driver, WebDriver):
            raise TypeError("driver는 Selenium WebDriver 인스턴스여야 합니다.")

        self.driver = driver
        self.config = config or BrowserClientConfig()

    # ----------------------------------------------------------
    # 기본 탐색 API
    # ----------------------------------------------------------
    def get(self, url: str) -> None:
        """지정된 URL로 이동합니다."""
        self.driver.get(url)

    def find(self, by: Any, value: str):
        """요소 찾기 (Selenium 기본 find_elements를 사용)"""
        return self.driver.find_elements(by, value)

    # ----------------------------------------------------------
    # Wait API (명시적 대기)
    # ----------------------------------------------------------
    def wait(self, fn: Callable, timeout: Optional[float] = None) -> Any:
        wait_timeout = timeout or self.config.wait_timeout
        waiter = WebDriverWait(self.driver, wait_timeout, poll_frequency=self.config.poll_frequency)
        return waiter.until(fn)

    # ----------------------------------------------------------
    # 페이지 소스 접근
    # ----------------------------------------------------------
    def page_source(self) -> str:
        return self.driver.page_source
    
    # ----------------------------------------------------------
    # 브라우저 종료
    # ----------------------------------------------------------
    def quit(self) -> None:
        self.driver.quit()

    # ----------------------------------------------------------
    # raw driver 제공 (기존 코드 호환)
    # ----------------------------------------------------------
    @property
    def raw(self) -> WebDriver:
        return self.driver


BrowserClient = SeleniumBrowserClient


__all__ = [
    "SeleniumBrowserClient",
    "BrowserClient",
]
