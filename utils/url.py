from urllib.parse import urlparse, urlunparse
import os

DEFAULT_BASE = "http://localhost/dvwa"

def normalize_base_url(url: str) -> str:
    """간단한 정규화: 스킴이 없으면 http 붙이고, 끝에 슬래시 제거"""
    if not url:
        return DEFAULT_BASE
    parsed = urlparse(url)
    if not parsed.scheme:
        # scheme이 없으면 http 기본으로 붙임
        parsed = urlparse("http://" + url)
    if not parsed.netloc:
        raise ValueError(f"Invalid base_url: {url}")
    # 재조합(포트 포함)
    normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))
    return normalized

def resolve_base_url(cli_arg: str = None, env_key: str = "S2N_BASE_URL", config_value: str = None, constructor_value: str = None) -> str:
    """
    우선순위 적용:
      1. cli_arg
      2. 환경변수 S2N_BASE_URL
      3. config_value (프로파일)
      4. constructor_value (기본 생성자 인자)
      5. DEFAULT_BASE
    """
    if cli_arg:
        return normalize_base_url(cli_arg)
    env = os.getenv(env_key)
    if env:
        return normalize_base_url(env)
    if config_value:
        return normalize_base_url(config_value)
    if constructor_value:
        return normalize_base_url(constructor_value)
    return normalize_base_url(None)