"""Utility helpers for the OS Command plugin."""

from __future__ import annotations

import re
import urllib.parse
from typing import List, Optional, Sequence


def extract_params(html: str, url: str, fallback_params: Sequence[str]) -> List[str]:
    """Extract candidate parameter names from HTML and URL query strings."""
    params = set()
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query)
    params.update(query.keys())

    for match in re.finditer(r'name=["\']?([a-z0-9_\-]+)["\']?', html, re.I):
        params.add(match.group(1))

    return list(params or fallback_params)


def build_attack_url(url: str, param: str, payload: str) -> str:
    """Return a GET URL with the provided payload injected into the param."""
    parsed = urllib.parse.urlparse(url)
    query = dict(urllib.parse.parse_qsl(parsed.query))
    query[param] = f"test{payload}"
    new_query = urllib.parse.urlencode(query)
    return parsed._replace(query=new_query).geturl()


def match_pattern(body: str, patterns: Sequence[str]) -> Optional[str]:
    """Return the first regex pattern that matches the response body."""
    for pattern in patterns:
        if re.search(pattern, body):
            return pattern
    return None

