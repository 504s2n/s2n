"""
DVWAAdapter + Selenium 통합 CLI
- DVWAAdapter로 로그인 시도
- requests.Session()에서 얻은 쿠키를 Selenium Chrome 브라우저에 주입
- 브라우저를 닫지 않으면 로그인된 세션 유지

사용 예:
  python cli_test_dvwa_selenium.py --base-url http://localhost/dvwa --user admin --pass password

옵션:
  --base-url    DVWA base URL (예: http://localhost/dvwa 또는 http://127.0.0.1:8081)
  --user        유저 이름 (기본: admin)
  --pass        비밀번호 (기본: password)
  --profile-dir Chrome 사용자 프로필을 사용하려면 경로 입력 (옵션)
  --headless    브라우저를 headless로 실행(디버깅 용도에는 권장하지 않음)
"""

import argparse
import sys
import time
from urllib.parse import urlparse, urlunparse
from os.path import dirname
from core.s2nscanner.http.client import HttpClient
from core.s2nscanner.auth.dvwa_adapter import DVWAAdapter

# Selenium imports
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager


def normalize_base_url(url: str) -> str:
    if not url:
        raise ValueError("base_url 값이 비어있습니다.")
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse("http://" + url)
    if not parsed.netloc:
        raise ValueError(f"Invalid base_url: {url}")
    path = parsed.path or ""
    lower = path.lower()
    looks_like_page = (
        lower.endswith(".php")
        or lower.endswith(".html")
        or any(p in lower for p in ("/login", "/index", "/setup", "/security"))
    )
    if looks_like_page:
        path = dirname(path)
    path = path.rstrip("/")
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager

def create_chrome_driver(use_profile: str = None, headless: bool = False):
    opts = Options()
    if use_profile:
        opts.add_argument(f"--user-data-dir={use_profile}")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    if headless:
        opts.add_argument("--headless=new")

    # webdriver-manager 로 드라이버 패치 경로 얻어서 Service로 전달
    service = ChromeService(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=opts)
    return driver


def main():
    parser = argparse.ArgumentParser(description="DVWA Adapter 테스트 (Selenium 기반)")
    parser.add_argument("--base-url", help="DVWA base URL (e.g. http://localhost/dvwa)")
    parser.add_argument("--user", help="사용자 이름", default="admin")
    parser.add_argument("--pass", dest="password", help="비밀번호", default="password")
    parser.add_argument("--profile-dir", help="(옵션) Chrome 사용자 프로필 경로 (프로필 지속용)")
    parser.add_argument("--headless", action="store_true", help="Headless 모드로 실행 (디버깅용 아님)")
    args = parser.parse_args()

    base_in = args.base_url
    if not base_in:
        base_in = input("DVWA base URL을 입력하세요 (예: http://localhost/dvwa): ").strip()
    try:
        base = normalize_base_url(base_in)
    except Exception as e:
        print(f"[ERROR] 잘못된 base_url: {e}")
        sys.exit(1)

    username, password = args.user, args.password
    print(f"[INFO] base_url: {base}")
    print(f"[INFO] credentials: {username} / {'*' * len(password)}")

    # 1) HttpClient + adapter로 로그인 시도
    client = HttpClient()
    adapter = DVWAAdapter(base_url=base)
    creds = [(username, password)]

    try:
        used = adapter.authenticate(client, creds)
    except Exception as e:
        print(f"[ERROR] authenticate 중 예외: {e}")
        sys.exit(1)
    if not used:
        print("[FAIL] 로그인 실패 — URL/계정/설정 상태 확인하세요.")
        sys.exit(1)
    print(f"[OK] Successful login: {used[0]}")

    # 2) requests.Session()에서 쿠키 획득
    cookies = client.s.cookies.get_dict()
    print(f"[INFO] 얻은 쿠키: {cookies}")

    # 3) Selenium 드라이버 생성
    try:
        driver = create_chrome_driver(use_profile=args.profile_dir, headless=args.headless)
    except Exception as e:
        print(f"[ERROR] Selenium 드라이버 생성 실패: {e}")
        print("권장 설치: pip install selenium webdriver-manager 그리고 Chrome 설치 확인")
        sys.exit(1)

    # 4) 먼저 도메인 로드 (쿠키 추가를 위해 동일 도메인으로 먼저 접근해야 함)
    # 예: http://localhost (도메인만 열어도 무방)
    parsed = urlparse(base)
    domain_root = f"{parsed.scheme}://{parsed.netloc}"
    driver.get(domain_root)
    time.sleep(0.5)  # 페이지 로드(브라우저가 도메인 세션을 초기화하도록 잠깐 대기)

    # 5) 쿠키 주입 (Selenium 형식으로 변환)
    # 주의: domain을 명시하면 때로는 'domain mismatch'가 생김. 안전하게 domain 필드 제외하거나 정확하게 설정.
    for name, value in cookies.items():
        cookie_dict = {
            "name": name,
            "value": value,
            "path": "/",
            # "domain": parsed.hostname,  # 일부 환경에서 필요시 사용
        }
        try:
            driver.add_cookie(cookie_dict)
        except Exception as e:
            print(f"[WARN] 쿠키 추가 실패({name}): {e} — 도메인/경로 설정 확인 필요")

    # 6) DVWA index로 이동 (로그인된 상태로 열림)
    driver.get(f"{base}/index.php")
    print("[OK] Selenium으로 로그인된 DVWA 페이지를 열었습니다. 브라우저를 닫지 않으면 세션 유지됩니다.")
    print("팁: 수동으로 페이지를 탐색하거나, 추가 자동화(테스트 스크립트)를 실행하실 수 있습니다.")

    # driver를 닫지 않으면 브라우저가 열린 채로 남음 — 사용자가 직접 창을 닫으면 세션 종료
    # 아래는 프로그램을 종료하지 않고 대기하는 간단 안내
    try:
        print("브라우저를 유지하려면 이 창을 닫지 마세요. 종료하려면 Ctrl+C를 누르세요.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] 종료 요청 수신 — 브라우저 닫기 및 프로그램 종료")
    finally:
        try:
            driver.quit()
        except:
            pass


if __name__ == "__main__":
    main()