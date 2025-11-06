# sqli_dvwa_helper.py

import requests
from urllib.parse import urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup

# =========================================================
# 유연한 모듈 임포트 처리
# =========================================================
try:
    # 1. 모듈 실행 시도 (상대 경로)
    from .sqli_config import SUCCESS_INDICATORS, ERROR_INDICATORS
except ImportError:
    # 2. 파일 직접 실행 시도 (절대 경로)
    from sqli_config import SUCCESS_INDICATORS, ERROR_INDICATORS


# =========================================================
# 헬퍼 함수
# =========================================================

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


# =========================================================
# 세션/인증 함수 (DVWA 로직 포함)
# =========================================================

def setup_session(full_url):
    """일반 세션을 초기화하고, 필요한 경우 인증 및 헤더 설정을 수행합니다."""
    session = requests.Session()

    # 브라우저 위장 헤더 추가
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36',
        'Referer': full_url
    })

    # DVWA 자동 로그인 로직
    if "dvwa" in full_url.lower() and "login.php" not in full_url.lower():
        dvwa_url = urlunparse(urlparse(full_url)._replace(path='/dvwa/login.php', query=''))
        dvwa_username = "admin"
        dvwa_password = "password"

        try:
            login_page = session.get(dvwa_url, timeout=10)
            soup = BeautifulSoup(login_page.text, 'html.parser')
            user_token_field = soup.find('input', {'name': 'user_token'})

            if user_token_field:
                user_token = user_token_field.get('value')
                login_data = {"username": dvwa_username, "password": dvwa_password, "user_token": user_token,
                              "Login": "Login"}
                session.post(dvwa_url, data=login_data, timeout=10)
                session.cookies.set("security", "low", domain=urlparse(full_url).netloc)
                security_url = urlunparse(urlparse(full_url)._replace(path='/dvwa/vulnerabilities/security.php'))
                session.get(security_url, params={'security': 'low'}, timeout=5)

        except requests.exceptions.RequestException:
            pass

    return session