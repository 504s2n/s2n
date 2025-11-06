import os
import json
import datetime

##### 유연한 모듈 임포트 처리 #####

try:
    # 1. 모듈 실행 시도 (상대 경로)
    from .brute_force_config import CACHE_FILE, CACHE_EXPIRY_DAYS
    from .brute_force_crawling import get_korean_password_list_with_selenium, url as crawl_url
except ImportError:
    # 2. 파일 직접 실행 시도 (절대 경로)
    from brute_force_config import CACHE_FILE, CACHE_EXPIRY_DAYS
    from brute_force_crawling import get_korean_password_list_with_selenium, url as crawl_url


def load_passwords_from_cache():
    """캐시 파일에서 비밀번호 목록을 로드하고 만료 여부를 확인합니다."""
    if os.path.exists(CACHE_FILE):
        try:
            file_mtime = os.path.getmtime(CACHE_FILE)
            cache_time = datetime.datetime.fromtimestamp(file_mtime)

            if datetime.datetime.now() - cache_time > datetime.timedelta(days=CACHE_EXPIRY_DAYS):
                print(f"[INFO] ⚠️ 캐시 파일이 {CACHE_EXPIRY_DAYS}일이 지나 만료되었습니다. 새로 크롤링합니다.")
                os.remove(CACHE_FILE)
                return None

            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                print(f"[INFO] ✅ 캐시 파일에서 {len(data)}개의 비밀번호를 빠르게 로드했습니다. (만료 전)")
                return data

        except Exception as e:
            print(f"[-] 캐시 파일 로드/만료 확인 오류 ({e}). 새로 크롤링을 시도합니다.")
            return None
    return None


def save_passwords_to_cache(passwords):
    """비밀번호 목록을 캐시 파일에 저장합니다."""
    try:
        # os.path.join() 대신 BASE_DIR을 사용하여 이미 절대 경로로 정의됨
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(passwords, f, ensure_ascii=False, indent=4)
        print(f"[INFO] 💾 {len(passwords)}개의 비밀번호를 '{CACHE_FILE}'에 캐시했습니다.")
    except Exception as e:
        print(f"[-] 캐시 파일 저장 오류: {e}")


def initialize_password_list():
    """크롤링/캐싱을 통해 최종 비밀번호 목록을 구성하고 반환합니다."""

    cached_passwords = load_passwords_from_cache()

    if cached_passwords:
        CRAWLED_PASSWORDS = cached_passwords
    else:
        print("[INFO] 🌐 캐시 파일 없음. 크롤링을 시작합니다. (시간 소요)")
        CRAWLED_PASSWORDS = get_korean_password_list_with_selenium(crawl_url)

        if CRAWLED_PASSWORDS:
            save_passwords_to_cache(CRAWLED_PASSWORDS)
        else:
            print("[-] 크롤링에 실패했습니다. 기본 목록도 사용하지 않고 종료합니다.")
            return []

    if CRAWLED_PASSWORDS:
        unique_passwords = []
        for p in CRAWLED_PASSWORDS:
            if p not in unique_passwords:
                unique_passwords.append(p)
        return unique_passwords

    return []