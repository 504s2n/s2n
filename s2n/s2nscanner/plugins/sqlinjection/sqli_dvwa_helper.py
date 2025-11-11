# sqli_dvwa_helper.py

import requests
from urllib.parse import urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup

# =========================================================
# 유연한 모듈 임포트 처리
# =========================================================
try:
    from .sqli_config import SUCCESS_INDICATORS, ERROR_INDICATORS
except ImportError:
    from sqli_config import SUCCESS_INDICATORS, ERROR_INDICATORS


def check_for_success_indicator(response_text):
    """DVWA SQLi 성공 시 응답 텍스트에 패턴이 포함되어 있는지 확인합니다."""
    text_lower = response_text.lower()
    for indicator in SUCCESS_INDICATORS:
        if indicator.lower() in text_lower:
            return indicator
    return None


def check_for_error_indicator(response_text):
    """일반적인 SQL 에러 키워드가 포함되어 있는지 확인합니다."""
    text_lower = response_text.lower()
    for indicator in ERROR_INDICATORS:
        if indicator.lower() in text_lower:
            return indicator
    return None


def extract_url_info(full_url):
    """전체 URL에서 기본 경로와 쿼리 파라미터 이름을 추출합니다."""
    parsed_url = urlparse(full_url)
    base_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))
    query_params = parse_qs(parsed_url.query)
    return base_url, list(query_params.keys())


# 세션 인증 함수 삭제