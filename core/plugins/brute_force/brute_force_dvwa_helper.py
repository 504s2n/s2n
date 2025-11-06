from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from urllib.parse import urlparse, urlunparse
import time

##### 유연한 모듈 임포트 처리 #####

try:
    from .brute_force_config import USER_FIELD_NAME
except ImportError:
    from brute_force_config import USER_FIELD_NAME


def perform_dvwa_login_and_setup(driver, full_url):
    """DVWA에 관리자 로그인하여 세션을 확보하고 보안 레벨을 'Low'로 설정합니다."""

    wait_long = WebDriverWait(driver, 20)
    parsed_url = urlparse(full_url)

    path_segments = parsed_url.path.split('/')
    try:
        dvwa_index = path_segments.index('dvwa')
        base_path = '/'.join(path_segments[:dvwa_index + 1]) + '/'
        base_url = urlunparse(parsed_url._replace(path=base_path, params='', query='', fragment=''))
    except ValueError:
        print("[-] DVWA 기본 URL을 추출할 수 없습니다. DVWA 설정을 건너뛰고 바로 스캔을 시도합니다.")
        return False, None

    LOGIN_URL = base_url + "login.php"
    SECURITY_URL = base_url + "security.php"

    driver.get(LOGIN_URL)

    try:
        username_input = wait_long.until(EC.presence_of_element_located((By.NAME, USER_FIELD_NAME)))
        password_input = wait_long.until(EC.presence_of_element_located((By.NAME, "password")))
        login_button = wait_long.until(EC.presence_of_element_located((By.NAME, "Login")))

        username_input.send_keys("admin")
        password_input.send_keys("password")
        login_button.click()
        time.sleep(2)

        if "Logout" not in driver.page_source:
            print("❌ 초기 로그인 실패. admin/password 또는 DVWA 상태를 확인하세요.")
            return False, base_url

        driver.get(SECURITY_URL)
        time.sleep(2)

        select_element = wait_long.until(EC.presence_of_element_located((By.NAME, "security")))
        Select(select_element).select_by_value('low')

        submit_button = driver.find_element(By.NAME, 'seclev_submit')
        submit_button.click()
        time.sleep(2)

        return True, base_url

    except Exception as e:
        print(f"❌ 초기 로그인 중 오류 발생: {type(e).__name__}. URL: {driver.current_url}")
        return False, base_url