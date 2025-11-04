"""
DVWA 전용 어댑터 (로그인/세션/환경설정)
- 목적: DVWA 사이트에 맞춘 인증/환경 조작을 캡슐화하여 플러그인에서 재사용 가능하게 함
- 입력: HttpClient 인스턴스 (세션을 래핑한 객체), creds 리스트 등
- 출력: 성공한 자격증명 튜플 | None
"""         

import re
from typing import List, Tuple, Optional
from core.s2nscanner.http.client import HttpClient


class DVWAAdapter:
    """
    DVWA 전용 어댑터 클래스
    - base: DVWA가 올라간 base URL
    - login_path: 로그인 페이지 경로 (기본 "/login.php")
    - security_paths: 보안레벨 변경 페이지 후보 경로들 (환경마다 차이 있을 수 있음)
    """

    def __init__(self, base_url: str, login_path: str = "/login.php", security_paths=None):
        self.base = base_url.rstrip("/")
        self.login_path = login_path
        # DVWA 배포마다 security page 위치가 다를 수 있어 후보를 둠
        self.security_paths = security_paths or ["/dvwa/security.php", "/security.php"]

    def _extract_user_token(self, text: str) -> Optional[str]:
        # DVWA의 CSRF 토큰을 HTML에서 뽑아냄. 입력(HTML 텍스트) -> 출력 (token 문자열 혹은 None)
        # 이유: DVWA는 로그인/설정 POST시 user_token을 요구할 수 있음
        m = re.search(r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']', text)
        return m.group(1) if m else None
    
    def authenticate(self, client: HttpClient, creds: List[Tuple[str, str]]):
        # client: HttpClient (requests.Session wrapper)
        # 1. Get 로그인 페이지 -> 유저토큰 추출, 있으면 POST에 포함
        # 2. POST 로그인 시도
        # 3. 결과페이지에 logout 표시가 있으면 성공으로 판단
        url = f"{self.base}{self.login_path}"
        for u, p in creds:
            try:
                # 1. 로그인 페이지 조회 (토큰 추출용)
                r = client.get(url, timeout=10)
                token = self._extract_user_token(r.text)

                #2. 로그인 POST 데이터 준비
                data = {"username": u, "password": p, "Login": "Login"}
                if token:
                    data["user_token"] = token
                
                # 3. 로그인 시도
                post = client.post(url, data=data, timeout=10)

                # 4. 간단 휴리스틱: 'logout.php' 링크/문구 등으로 성공 판단
                if "logout.php" in (post.text or "") or "Logout" in (post.text or ""):
                    return (u, p)
                if "Login" not in (post.text or ""):
                    return (u, p)
            
            except Exception:
                continue
        return None
    

def finalize(self, clinet: HttpClient):
    return