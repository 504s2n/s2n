import os

# 파일이 위치한 디렉토리 경로를 기준으로 절대 경로 구성
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- 🌟 Brute Force 스캐너 설정 (데이터 연동) 🌟 ---
USERNAME_LIST = ["admin", "user", "test", "root"]

# 캐시 경로 설정 (brute_force 폴더 내부에 파일이 생성됨)
CACHE_FILE = os.path.join(BASE_DIR, 'password_crawling_cache.json')
CACHE_EXPIRY_DAYS = 3

# --- 🚨 성공/실패 지표 설정 ---
DVWA_SUCCESS_INDICATORS = ["Welcome to the password protected area", "Logout"]
DVWA_FAILURE_INDICATORS = ["Username and/or password incorrect", "Login Failed", "login and/or password incorrect"]
GENERIC_SUCCESS_INDICATORS = ["✅ 로그인 성공: 환영합니다"]
GENERIC_FAILURE_INDICATORS = ["❌ 사용자 이름 또는 비밀번호가 올바르지 않습니다"]

# --- Selenium 요소 정의 ---
USER_FIELD_NAME = "username"
PASS_FIELD_NAME = "password"
LOGIN_BUTTON_NAME = "Login"