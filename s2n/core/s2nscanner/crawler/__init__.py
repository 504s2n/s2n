from __future__ import annotations
import re
import urllib.parse
from collections import deque
from typing import List
import logging

logger = logging.getLogger("s2n.crawler")

def crawl_recursive(base_url: str, client, depth: int = 2, timeout: int = 5) -> List[str]:
    visited = set()
    to_visit = deque([(base_url, 0)])
    found_links = []

    parsed_base = urllib.parse.urlparse(base_url)

    while to_visit:
        url, d = to_visit.popleft()
        if d > depth or url in visited:
            continue
        visited.add(url)

        try:
            resp = client.get(url, timeout=timeout)
            html = resp.text or ""
        except Exception:
            logger.debug("crawl: failed to GET %s", url, exc_info=True)
            continue

        found_links.append(url)

        for tag, attr in [
            ("a", "href"), ("form", "action"),
            ("script", "src"), ("iframe", "src"),
            ("link", "href")
        ]:
            for m in re.finditer(fr"<{tag}[^>]+{attr}=['\"]([^'\"]+)['\"]", html, re.I):
                link = m.group(1)
                if not link:
                    continue
                if link.startswith(("mailto:", "javascript:")):
                    continue
                full = urllib.parse.urljoin(url, link)
                parsed = urllib.parse.urlparse(full)
                if parsed.netloc == parsed_base.netloc:
                    if full not in visited:
                        to_visit.append((full, d + 1))

    return list(dict.fromkeys(found_links))