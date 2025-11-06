import sys
from urllib.parse import urlparse
import time

##### 모듈 임포트: 실행 환경에 따라 상대/절대 경로 자동 선택 #####
try:
    # 1. 모듈 실행 시도 (상대 경로)
    from .brute_force_cache import initialize_password_list
    from .brute_force_selenium import setup_driver, scan_brute_force_with_selenium
    from .brute_force_dvwa_helper import perform_dvwa_login_and_setup
    from .brute_force_crawling import url as crawl_url
except ImportError:
    # 2. 파일 직접 실행 시도 (절대 경로)
    from brute_force_cache import initialize_password_list
    from brute_force_selenium import setup_driver, scan_brute_force_with_selenium
    from brute_force_dvwa_helper import perform_dvwa_login_and_setup
    from brute_force_crawling import url as crawl_url


def print_password_list(password_list, source_url):
    """비밀번호 목록 중 일부를 포맷팅하여 출력합니다."""

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
        line = [f"{i + 1}위: {passwords_to_display[i]}" for i in range(current_index, end_index)]
        print('  ' + ' | '.join(line))
        current_index = end_index

    print(f"\n비밀번호 출처 : {source_url}")
    print("-------------------------------------")


def main():
    print("--- 🛡️ Brute Force (무차별 대입) 탐지 스캐너 ---")

    full_url = input("테스트할 Brute Force 취약점 페이지 전체 URL을 입력하세요 : ").strip()

    if not full_url.startswith('http'):
        print("[-] URL은 'http' 또는 'https'로 시작해야 합니다. 종료합니다.")
        sys.exit(1)

    PASSWORD_LIST = initialize_password_list()

    if not PASSWORD_LIST:
        print("\n❌ 스캐너 실패: 유효한 사전 공격 목록을 확보하지 못했습니다.")
        print_password_list([], crawl_url)
        sys.exit(1)

    print_password_list(PASSWORD_LIST, crawl_url)
    passwords_to_attempt = PASSWORD_LIST[:20]

    driver = None
    results = []

    try:
        driver = setup_driver()
        is_dvwa = "/dvwa/" in full_url.lower()

        if is_dvwa:
            success, base_url = perform_dvwa_login_and_setup(driver, full_url)
            if not success:
                print("❌ DVWA 초기 설정에 실패하여 스캔을 중단합니다.")
                return

        results = scan_brute_force_with_selenium(driver, full_url, passwords_to_attempt, is_dvwa)

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