"""
DVWAAdapter (로그인·세션·재사용 전용)
- 목적: 플러그인이나 main에서 DVWA 로그인 세션을 공유할 수 있도록 관리
- 기능:
  1. authenticate(creds): 로그인 시도, 성공 시 (user, pass) 반환
  2. is_authenticated(): index.php 요청으로 세션 유지 여부 검사
  3. ensure_authenticated(): 세션 만료 시 자동 재로그인
  4. get_client(): 현재 세션 HttpClient 반환
  5. save_cookies(), load_cookies(): 쿠키 저장/복원
- 사용 예시 (main.py 등에서):
      adapter = DVWAAdapter(base_url="http://localhost/dvwa")
      adapter.ensure_authenticated([("admin", "password")])
      client = adapter.get_client()
      r = client.get("http://localhost/dvwa/vulnerabilities/exec/")
"""

import re
import json
import time
from threading import Lock
from typing import List, Tuple, Optional, Dict
from urllib.parse import urljoin
from s2n.s2nscanner.http.client import HttpClient

class DVWAAdapter:
    def __init__(self, base_url: str, login_path="/login.php", index_path="/index.php", client: Optional[HttpClient] = None):
        if not base_url:
            raise ValueError("base_url을 지정하세요 (예: http://localhost/dvwa)")
        self.base = base_url.rstrip("/")
        self.login_path = login_path
        self.index_path = index_path
        self._client = client or HttpClient()
        self._lock = Lock()
        self._last_auth = None

    # 내부: CSRF 토큰 추출
    def _extract_user_token(self, text: str) -> Optional[str]:
        match = re.search(r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']', text)
        return match.group(1) if match else None

    # 로그인 시도
    def authenticate(self, creds: List[Tuple[str, str]]) -> Optional[Tuple[str, str]]:
        """DVWA 로그인 시도, 성공 시 (username, password) 반환"""
        url = f"{self.base}{self.login_path}"
        for user, pw in creds:
            try:
                # 로그인 페이지에서 토큰 추출
                resp = self._client.get(url, timeout=10)
                token = self._extract_user_token(resp.text)
                data = {"username": user, "password": pw, "Login": "Login"}
                if token:
                    data["user_token"] = token
                post = self._client.post(url, data=data, timeout=10)
                if "logout.php" in (post.text or "") or "Logout" in (post.text or ""):
                    self._last_auth = (user, pw, time.time())
                    return (user, pw)
            except Exception:
                continue
        return None

    # 세션 유지 여부 검사
    def is_authenticated(self) -> bool:
        """index.php 요청 시 로그인 상태면 True"""
        try:
            test_url = f"{self.base}{self.index_path}"
            r = self._client.get(test_url, timeout=5)
            text = r.text or ""
            return "logout.php" in text or "Logout" in text
        except Exception:
            return False

    # 세션 자동 유지
    def ensure_authenticated(self, creds: List[Tuple[str, str]], retries=1):
        """세션이 끊기면 자동으로 재로그인"""
        if self.is_authenticated():
            return True
        for _ in range(retries + 1):
            used = self.authenticate(creds)
            if used:
                return True
            time.sleep(1)
        return False

    # 공용 client 반환
    def get_client(self) -> HttpClient:
        """현재 세션이 담긴 HttpClient 반환"""
        return self._client

    # 쿠키 저장/복원
    def save_cookies(self, path: str):
        """현재 세션 쿠키를 JSON으로 저장"""
        try:
            cookies = self._client.s.cookies.get_dict()
            with open(path, "w", encoding="utf-8") as f:
                json.dump(cookies, f, ensure_ascii=False, indent=2)
            print(f"[INFO] 쿠키 저장 완료: {path}")
        except Exception as e:
            print(f"[WARN] 쿠키 저장 실패: {e}")
    def load_cookies(self, path: str):
        """저장된 쿠키 JSON을 불러와 세션에 주입"""
        try:
            with open(path, "r", encoding="utf-8") as f:
                cookies = json.load(f)
            for k, v in cookies.items():
                self._client.s.cookies.set(k, v)
            print(f"[INFO] 쿠키 복원 완료: {path}")
        except Exception as e:
            print(f"[WARN] 쿠키 복원 실패: {e}")