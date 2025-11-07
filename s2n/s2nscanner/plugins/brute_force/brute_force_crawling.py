from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
import time

url = "https://nordpass.com/most-common-passwords-list/"


def get_korean_password_list_with_selenium(target_url):
    passwords_list = []
    driver = None

    options = webdriver.ChromeOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('log-level=3')
    service = Service()

    try:
        driver = webdriver.Chrome(service=service, options=options)
        driver.get(target_url)
        wait = WebDriverWait(driver, 30)

        SELECT_XPATH = "//select"
        select_element = wait.until(
            EC.presence_of_element_located((By.XPATH, SELECT_XPATH))
        )
        selector = Select(select_element)
        selector.select_by_value('kr')

        # 데이터 업데이트를 위한 대기 조건 (1q2w3e는 현재 한국 목록의 1위로 추정)
        KOREAN_FIRST_PASSWORD = '1q2w3e'
        ROW_XPATH = "//div[contains(@class, 'flex gap-3') and contains(@class, 'border-b')]"
        FIRST_PASSWORD_ELEMENT_XPATH = f"{ROW_XPATH}[1]//div[2]"

        try:
            wait.until(
                EC.text_to_be_present_in_element((By.XPATH, FIRST_PASSWORD_ELEMENT_XPATH), KOREAN_FIRST_PASSWORD)
            )
            time.sleep(1)

        except Exception:
            time.sleep(5)

        rows = driver.find_elements(By.XPATH, ROW_XPATH)

        for i, row in enumerate(rows):
            if len(passwords_list) >= 20:
                break

            try:
                cols = row.find_elements(By.TAG_NAME, 'div')

                if len(cols) >= 2:
                    password = cols[1].text.strip()

                    if password and len(password) > 2 and len(password.split()) == 1:
                        passwords_list.append(password)

            except:
                continue

        return passwords_list


    except Exception:
        return []

    finally:
        if driver:
            driver.quit()