from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, Optional

# 패키지 실행(모듈로 import)과 직접 실행(python xss.py)을 모두 지원하기 위한 import 처리
if __package__ is None or __package__ == "":
    # 스크립트를 직접 실행할 때 scanner.py가 같은 폴더에 있으면 그 경로를 sys.path에 추가하여
    # 상대경로 import가 가능하도록 합니다. 패키지 컨텍스트라면 상대 import를 사용합니다.
    APP_DIR = Path(__file__).resolve().parent
    if str(APP_DIR) not in sys.path:
        sys.path.append(str(APP_DIR))
    from xss_scanner import ReflectedScanner
else:
    from .xss_scanner import ReflectedScanner


# 사용자 입력을 안전하게 받아오는 헬퍼 함수
# Ctrl+C 또는 Ctrl+D(EOF)가 입력되면 예외를 잡아 깔끔하게 종료합니다.
def _prompt(message: str) -> str:
    try:
        return input(message)
    except (KeyboardInterrupt, EOFError):
        print("\nAborted by user.")
        sys.exit(0)


# 페이로드 파일(xss_payloads.json)을 찾는 함수
# 1) 현재 작업 디렉토리에서 조회
# 2) 이 스크립트 파일과 동일한 디렉토리에서 조회
# 위 둘 다 실패하면 FileNotFoundError를 발생시켜 호출자에게 알립니다.
def _load_payload_path() -> Path:
    payload_name = "xss_payloads.json"
    cwd_path = Path(payload_name)
    if cwd_path.exists():
        return cwd_path

    script_path = Path(__file__).parent / payload_name
    if script_path.exists():
        return script_path

    raise FileNotFoundError(f"Payload file not found: {payload_name}")


# 쿠키 문자열을 파싱하여 딕셔너리로 변환하는 유틸리티
# 입력 예시: "SESSION=abc123; csrftoken=xyz" -> {"SESSION": "abc123", "csrftoken": "xyz"}
def _parse_cookies(raw: str) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    for pair in raw.split(";"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


# 프로그램 진입 함수(main)
# 1) 페이로드 파일 경로 확인
# 2) 사용자로부터 타겟 URL 및 쿠키 입력 수집
# 3) ReflectedScanner 생성 및 scan 수행
# 4) 결과 요약 출력 및 사용자 선택에 따라 JSON 저장
# 정상 종료 시 0, 오류 또는 입력 누락 시 1을 반환합니다.
def main() -> int:
    logger = logging.getLogger("s2n_xss")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        payload_path = _load_payload_path()
    except FileNotFoundError as exc:
        print(exc)
        return 1

    # CLI 헤더 출력 (사용자에게 도구 이름과 구분선 표시)
    print("=" * 70)
    print("s2n_xss - Reflected XSS Vulnerability Scanner")
    print("=" * 70)

    # 타겟 URL을 사용자에게 입력 받음 (예: http://example.com/search?q=test)
    target_url = _prompt("\n[>] Enter target URL: ").strip()
    if not target_url:
        print("No target provided.")
        return 1

    # 필요 시 쿠키 문자열 입력(세션 유지가 필요한 경우). 빈 입력 허용
    cookies_input = _prompt("[>] Enter cookies (key=value;key2=value2) or blank: ").strip()
    cookies: Optional[Dict[str, str]] = None
    if cookies_input:
        cookies = _parse_cookies(cookies_input)

    print()  # 입력 프롬프트와 이후 로그 사이에 한 줄 공백 삽입
    sys.stdout.flush()

    # ReflectedScanner 인스턴스 생성: 페이로드 경로와 쿠키(있다면) 전달
    scanner = ReflectedScanner(payload_path, cookies)
    # 스캔 실행: target_url을 사용하여 자동으로 입력 지점 탐지 및 페이로드 테스트 수행
    results = scanner.scan(target_url)
    # 스캔 결과 요약을 콘솔에 출력 (감지된 취약점 수, 예시 등)
    scanner.print_summary()

    # 결과가 존재하면 사용자가 원할 경우 JSON 파일로 저장할 수 있도록 선택지 제공
    if results:
        save = _prompt("\n[?] Save results to JSON? (y/n): ").strip().lower()
        if save == "y":
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            out_path = Path.cwd() / f"xss_reflected_results_{timestamp}.json"
            with out_path.open("w", encoding="utf-8") as fp:
                json.dump(results, fp, ensure_ascii=False, indent=2)
            print(f"Saved to {out_path}")

    return 0


# 이 파일을 직접 실행할 때 main()을 호출하여 프로그램을 시작
if __name__ == "__main__":
    sys.exit(main())
