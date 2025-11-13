import os
import json
import datetime
import logging

# 모듈 임포트
from .brute_force_config import CACHE_FILE, CACHE_EXPIRY_DAYS
from .brute_force_crawling import get_korean_password_list_with_selenium, url as crawl_url


def load_passwords_from_cache(logger: logging.Logger):
    """캐시 파일에서 비밀번호 목록을 로드하고 만료 여부를 확인합니다."""
    if os.path.exists(CACHE_FILE):
        try:
            file_mtime = os.path.getmtime(CACHE_FILE)
            cache_time = datetime.datetime.fromtimestamp(file_mtime)

            if datetime.datetime.now() - cache_time > datetime.timedelta(days=CACHE_EXPIRY_DAYS):
                logger.warning(f"⚠️ 캐시 파일이 {CACHE_EXPIRY_DAYS}일이 지나 만료되었습니다. 새로 크롤링합니다.")
                os.remove(CACHE_FILE)
                return None

            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                logger.info(f"✅ 캐시 파일에서 {len(data)}개의 비밀번호를 빠르게 로드했습니다. (만료 전)")
                return data

        except Exception as e:
            logger.error(f"[-] 캐시 파일 로드/만료 확인 오류 ({e}). 새로 크롤링을 시도합니다.")
            return None
    return None


def save_passwords_to_cache(passwords, logger: logging.Logger):
    """비밀번호 목록을 캐시 파일에 저장합니다."""
    try:
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(passwords, f, ensure_ascii=False, indent=4)
        logger.info(f"💾 {len(passwords)}개의 비밀번호를 '{CACHE_FILE}'에 캐시했습니다.")
    except Exception as e:
        logger.error(f"[-] 쿠키 저장 실패: {e}")


def initialize_password_list(logger: logging.Logger):
    """크롤링/캐싱을 통해 최종 비밀번호 목록을 구성하고 반환합니다."""

    cached_passwords = load_passwords_from_cache(logger)

    if cached_passwords:
        CRAWLED_PASSWORDS = cached_passwords
    else:
        logger.info("🌐 캐시 파일 없음. 크롤링을 시작합니다. (시간 소요)")
        CRAWLED_PASSWORDS = get_korean_password_list_with_selenium(crawl_url, logger)

        if CRAWLED_PASSWORDS:
            save_passwords_to_cache(CRAWLED_PASSWORDS, logger) # logger 전달
        else:
            logger.error("[-] 크롤링에 실패했습니다. 기본 목록도 사용하지 않고 종료합니다.")
            return []

    # 중복 제거 로직
    if CRAWLED_PASSWORDS:
        unique_passwords = []
        for p in CRAWLED_PASSWORDS:
            if p not in unique_passwords:
                unique_passwords.append(p)
        return unique_passwords

    return []