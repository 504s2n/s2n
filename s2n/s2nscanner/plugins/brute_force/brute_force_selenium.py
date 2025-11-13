from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import random
import os
import sys
import logging
from typing import List, Optional, Dict
from webdriver_manager.chrome import ChromeDriverManager
from .brute_force_config import (
    DVWA_SUCCESS_INDICATORS, DVWA_FAILURE_INDICATORS,
    GENERIC_SUCCESS_INDICATORS, GENERIC_FAILURE_INDICATORS,
    USER_FIELD_NAME, PASS_FIELD_NAME, LOGIN_BUTTON_NAME, USERNAME_LIST
)


def setup_driver(logger: logging.Logger):

    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')

    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    options.add_argument('--log-level=3')

    log_path = 'NUL' if sys.platform == 'win32' else os.devnull

    return webdriver.Chrome(
        service=Service(
            executable_path=ChromeDriverManager().install(),
            log_path=log_path
        ),
        options=options
    )


def scan_brute_force_with_selenium(
        driver, target_url: str, passwords_to_attempt: List[str], is_dvwa: bool, logger: logging.Logger
) -> Optional[Dict[str, str]]:  # logger 인자 추가 및 반환 타입 정의

    success_details: Optional[Dict[str, str]] = None
    wait = WebDriverWait(driver, 15)

    success_indicators = DVWA_SUCCESS_INDICATORS if is_dvwa else GENERIC_SUCCESS_INDICATORS
    failure_indicators = DVWA_FAILURE_INDICATORS if is_dvwa else GENERIC_FAILURE_INDICATORS

    shuffled_usernames = USERNAME_LIST[:]
    random.shuffle(shuffled_usernames)

    logger.info(f"{target_url} 페이지로 이동하여 스캔 시작...")
    driver.get(target_url)

    total_attempts = len(shuffled_usernames) * len(passwords_to_attempt)
    logger.info(f"[+] Brute Force 스캔 시작: 총 {total_attempts}가지 조합 시도.")

    USER_FIELD = (By.NAME, USER_FIELD_NAME)
    PASS_FIELD = (By.NAME, PASS_FIELD_NAME)
    LOGIN_BUTTON = (By.NAME, LOGIN_BUTTON_NAME)

    for user in shuffled_usernames:
        for passwd in passwords_to_attempt:

            # burte_force 공격 시도하는 흔적 보이려면 주석해제
            # logger.debug(f"시도: ID='{user}', PW='{passwd}'")  # 시도 정보 로깅 추가

            try:
                username_input = wait.until(EC.presence_of_element_located(USER_FIELD))
                password_input = wait.until(EC.presence_of_element_located(PASS_FIELD))
                login_button = wait.until(EC.presence_of_element_located(LOGIN_BUTTON))
            except Exception:
                logger.error("로그인 폼 필드를 찾을 수 없어 스캔을 중단합니다.")
                return success_details  # None 반환

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
                # 성공 시 딕셔너리 반환 (Finding 생성을 위해)
                return {'user': user, 'password': passwd}

            pass

    return success_details