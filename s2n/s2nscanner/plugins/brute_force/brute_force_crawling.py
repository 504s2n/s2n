from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
import time
import logging

url = "https://nordpass.com/most-common-passwords-list/"


def get_korean_password_list_with_selenium(target_url: str, logger: logging.Logger):
    passwords_list = []
    driver = None

    # Selenium 드라이버 설정
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('log-level=3')
    service = Service()

    logger.debug(f"크롤링 시작: {target_url} (Selenium Headless)")

    try:
        driver = webdriver.Chrome(service=service, options=options)
        driver.get(target_url)
        wait = WebDriverWait(driver, 30)

        # 1. 한국어 목록 선택
        SELECT_XPATH = "//select"
        select_element = wait.until(
            EC.presence_of_element_located((By.XPATH, SELECT_XPATH))
        )
        selector = Select(select_element)
        selector.select_by_value('kr')
        logger.debug("한국어 목록으로 셀렉터 변경")

        # 2. 데이터 업데이트 대기
        KOREAN_FIRST_PASSWORD = '1q2w3e'
        ROW_XPATH = "//div[contains(@class, 'flex gap-3') and contains(@class, 'border-b')]"
        FIRST_PASSWORD_ELEMENT_XPATH = f"{ROW_XPATH}[1]//div[2]"

        try:
            wait.until(
                EC.text_to_be_present_in_element((By.XPATH, FIRST_PASSWORD_ELEMENT_XPATH), KOREAN_FIRST_PASSWORD)
            )
            logger.debug(f"데이터 업데이트 완료 확인 (첫 번째 비밀번호: {KOREAN_FIRST_PASSWORD})")

        except Exception:
            logger.warning("데이터 업데이트 확인 실패. 5초 추가 대기합니다.")
            time.sleep(5)

        # 3. 비밀번호 추출
        rows = driver.find_elements(By.XPATH, ROW_XPATH)

        for i, row in enumerate(rows):
            if len(passwords_list) >= 20:  # 20개까지만 크롤링
                break

            try:
                cols = row.find_elements(By.TAG_NAME, 'div')

                if len(cols) >= 2:
                    password = cols[1].text.strip()

                    if password and len(password) > 2 and len(password.split()) == 1:
                        passwords_list.append(password)

            except Exception as e:
                logger.debug(f"행 처리 중 오류 발생: {e}")
                continue

        logger.info(f"크롤링 완료: {len(passwords_list)}개의 비밀번호 추출.")
        return passwords_list


    except Exception as e:
        logger.error(f"크롤링 중 오류 발생: {type(e).__name__} - {e}")
        return []

    finally:
        if driver:
            driver.quit()