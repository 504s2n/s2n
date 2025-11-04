#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DVWAAdapter + Selenium CLI (CLI 입력 방식 전용)
- 목적: CLI 인자(--base-url, --user, --pass 혹은 --creds user:pass)를 통해 DVWA에 로그인하고,
       로그인된 상태의 Chrome 창을 열어 세션을 유지하게 함.
- 우선순위: --creds > (--user and --pass) > (대화형 입력)
- 대화형 입력시 비밀번호는 getpass로 마스킹 처리됩니다.
- 사용 예:
    python cli_test_dvwa_selenium.py --base-url http://localhost/dvwa --creds admin:password --open-browser
    python cli_test_dvwa_selenium.py --base-url http://localhost/dvwa --user admin  # 그럼 비밀번호는 물어봄
"""

import argparse
import sys
import time
import getpass
from urllib.parse import urlparse, urlunparse
from os.path import dirname

# 프로젝트 내부 모듈(기획 문서에 따라 core 경로 사용)
from core.s2nscanner.http.client import HttpClient
from core.s2nscanner.auth.dvwa_adapter import DVWAAdapter

# Selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager


# -----------------------
# 유틸: base_url 정규화
# -----------------------
def normalize_base_url(url: str) -> str:
    """
    - 스킴이 없으면 http:// 자동 추가
    - 페이지(/login.php 등)를 입력해도 디렉토리(/dvwa)까지만 남김
    - 끝의 슬래시 제거
    """
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


# -----------------------
# 유틸: Chrome 드라이버 생성 (webdriver-manager + Service 사용)
# -----------------------
def create_chrome_driver(use_profile: str = None, headless: bool = False):
    opts = Options()
    if use_profile:
        opts.add_argument(f"--user-data-dir={use_profile}")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    # headless 옵션을 켤 때 환경에 따라 호환성 차이 있을 수 있음
    if headless:
        opts.add_argument("--headless=new")

    # webdriver-manager가 내려준 드라이버 경로를 Service로 전달
    service = ChromeService(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=opts)
    return driver


# -----------------------
# 자격증명 해석 (CLI 전용: --creds 또는 --user/--pass 사용)
# -----------------------
def resolve_credentials(args):
    """
    우선순위:
      1) --creds user:pass
      2) --user + --pass
      3) 대화형 입력 (username, getpass)
    반환: (username, password)
    """
    # 1) --creds
    if getattr(args, "creds", None):
        raw = args.creds
        if ":" not in raw:
            raise ValueError("--creds는 user:pass 형식이어야 합니다.")
        user, pwd = raw.split(":", 1)
        return user, pwd

    # 2) --user + --pass
    if getattr(args, "user", None) and getattr(args, "password", None):
        return args.user, args.password

    # 3) --user만 있고 --pass 없으면 대화형으로 비밀번호 물어봄
    if getattr(args, "user", None) and not getattr(args, "password", None):
        pwd = getpass.getpass("DVWA 비밀번호를 입력하세요: ")
        return args.user, pwd

    # 4) 대화형: username/password 모두 물어보기
    user = input("DVWA 사용자 이름을 입력하세요: ").strip()
    pwd = getpass.getpass("DVWA 비밀번호를 입력하세요: ")
    return user, pwd


# -----------------------
# 브라우저에 쿠키 주입하고 DVWA 열기 (Selenium)
# -----------------------
def open_logged_browser(base_url: str, cookies: dict, profile_dir: str = None, headless: bool = False):
    """
    - base_url: 정규화된 DVWA base (예: http://localhost/dvwa)
    - cookies: requests.Session().cookies.get_dict() 결과
    """
    driver = create_chrome_driver(use_profile=profile_dir, headless=headless)

    # 쿠키를 추가하려면 동일 도메인으로 먼저 접근해야 함
    parsed = urlparse(base_url)
    domain_root = f"{parsed.scheme}://{parsed.netloc}"
    driver.get(domain_root)
    time.sleep(0.5)  # 도메인 초기화 대기

    # Selenium은 쿠키 dict에 domain이 정확해야 할 수 있음. domain을 아예 넣지 않으면 안전한 경우가 많음.
    for name, val in cookies.items():
        cookie = {"name": name, "value": val, "path": "/"}
        try:
            driver.add_cookie(cookie)
        except Exception as e:
            # 실패해도 계속 진행 — 일부 환경에서는 domain/secure 관련으로 실패할 수 있음.
            print(f"[WARN] 쿠키 추가 실패({name}): {e}")

    # DVWA index 열기 (로그인된 상태로 열림)
    driver.get(f"{base_url}/index.php")
    print("[OK] Selenium으로 로그인된 DVWA 페이지를 열었습니다. 브라우저를 닫지 않으면 세션 유지됩니다.")
    print("팁: 이제 수동으로 페이지를 탐색하거나 자동화 스크립트를 실행하세요.")
    return driver


# -----------------------
# 메인
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="DVWAAdapter 테스트 (Selenium 기반, CLI 입력 전용)")
    parser.add_argument("--base-url", help="DVWA base URL (예: http://localhost/dvwa)", required=False)
    parser.add_argument("--creds", help="user:pass 형식으로 빠르게 전달 (우선순위)", required=False)
    parser.add_argument("--user", help="사용자 이름 (대화형/인자)", required=False)
    parser.add_argument("--pass", dest="password", help="비밀번호 (대화형/인자)", required=False)
    parser.add_argument("--profile-dir", help="Chrome 사용자 프로필 경로(옵션)", required=False)
    parser.add_argument("--headless", action="store_true", help="Headless 모드로 실행(권장하지 않음)", required=False)
    args = parser.parse_args()

    # 1) base_url 확보 (필수)
    base_in = args.base_url
    if not base_in:
        base_in = input("DVWA base URL을 입력하세요 (예: http://localhost/dvwa): ").strip()
    try:
        base = normalize_base_url(base_in)
    except Exception as e:
        print(f"[ERROR] 잘못된 base_url: {e}")
        sys.exit(1)

    # 2) credentials 확보 (CLI 우선)
    try:
        username, password = resolve_credentials(args)
    except Exception as e:
        print(f"[ERROR] credentials 파싱 오류: {e}")
        sys.exit(1)

    print(f"[INFO] 사용된 base_url: {base}")
    print(f"[INFO] 크리덴셜: {username} / {'*' * len(password)}")

    # 3) HttpClient + DVWAAdapter로 로그인 시도
    client = HttpClient()
    adapter = DVWAAdapter(base_url=base)
    creds = [(username, password)]

    try:
        used = adapter.authenticate(client, creds)
    except Exception as e:
        print(f"[ERROR] authenticate 중 예외 발생: {e}")
        sys.exit(1)

    if not used:
        print("[FAIL] 로그인 실패 — URL/계정/설정 상태 확인하세요.")
        sys.exit(1)

    print(f"[OK] Successful login: {used[0]}")

    # 4) 세션 쿠키 획득
    cookies = client.s.cookies.get_dict()
    print(f"[INFO] 얻은 쿠키: {cookies}")

    # 5) 브라우저 자동 오픈(옵션: 항상 열도록 설계)
    try:
        driver = open_logged_browser(base, cookies, profile_dir=args.profile_dir, headless=args.headless)
    except Exception as e:
        print(f"[ERROR] 브라우저 오픈 실패: {e}")
        sys.exit(1)

    # 6) 브라우저를 닫을 때까지 대기 (Ctrl+C로 종료)
    try:
        print("브라우저를 유지하려면 이 터미널을 닫지 마세요. 종료하려면 Ctrl+C를 누르세요.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] 종료 요청 수신 — 브라우저 종료 및 프로그램 종료")
    finally:
        try:
            driver.quit()
        except Exception:
            pass


if __name__ == "__main__":
    main()