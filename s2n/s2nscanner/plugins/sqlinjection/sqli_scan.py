import uuid
import time
import requests
from typing import List, Optional
from bs4 import BeautifulSoup
import requests.compat

from s2n.s2nscanner.clients.http_client import HttpClient
from s2n.s2nscanner.interfaces import (
    PluginContext,
    Finding,
    Severity,
    Confidence,
)
from s2n.s2nscanner.logger import get_logger
from s2n.s2nscanner.plugins.sqlinjection.sqli_config import (
    TEST_PAYLOAD,
    TEST_PAYLOAD_TIME_BLIND,
    TIME_THRESHOLD,
)
from s2n.s2nscanner.plugins.sqlinjection.sqli_dvwa_helper import (
    check_for_success_indicator,
    check_for_error_indicator,
    extract_url_info,
)
from s2n.s2nscanner.crawler import crawl_recursive

logger = get_logger("plugins.sqlinjection")


def sqli_scan(
    target_url: str,
    depth: int,
    timeout: int,
    http_client: Optional[HttpClient] = None,
    plugin_context: Optional[PluginContext] = None,
) -> List[Finding]:
    """
    Scans the target URL for SQL Injection vulnerabilities.
    """
    results: List[Finding] = []
    context_logger = getattr(plugin_context, "logger", None) or logger

    # Ensure http_client is available
    if http_client is None:
        context_logger.error("HttpClient is required for sqli_scan.")
        return results

    try:
        base_url, get_params_from_url = extract_url_info(target_url)
    except Exception as e:
        context_logger.error(f"URL parsing error: {e}")
        return results

    # 1. Scan GET parameters
    targets = crawl_recursive(base_url, http_client, depth=depth, timeout=timeout) or [base_url]
    for target in targets:
        get_findings = _scan_get_param(http_client, base_url, target, get_params_from_url)
        results.extend(get_findings)
        form_findings = _scan_forms(http_client, target)
        results.extend(form_findings)

    return results


def _create_finding(
    vul_type: str,
    severity: Severity,
    url: str,
    payload: Optional[str],
    method: str,
    param: str,
    details: str,
) -> Finding:
    title_map = {
        "SQL Injection (Data Retrieval/Boolean)": "SQL Injection (Data Exposure)",
        "SQL Injection (Error Based)": "SQL Injection (Error Message)",
        "SQL Injection (Time Based)": "SQL Injection (Blind)",
    }

    return Finding(
        id=str(uuid.uuid4()),
        plugin="sqlinjection",
        severity=severity,
        title=title_map.get(vul_type, "SQL Injection Detected"),
        description=f"URL: {url}에서 {method} 요청의 파라미터 '{param}'에서 {vul_type} 징후가 발견되었습니다. 상세: {details}",
        url=url,
        method=method,
        parameter=param,
        payload=payload if payload else None,
        evidence=details,
        confidence=Confidence.FIRM,
    )


def _scan_get_param(
    client: HttpClient, base_url: str, full_url: str, param_names: List[str]
) -> List[Finding]:
    vulnerabilities = []
    success_payload = "' OR '1'='1' -- "

    for param in param_names:
        # 1. Success/Error based detection
        attack_url = f"{base_url}?{param}=1{success_payload}"
        try:
            response = client.get(attack_url, timeout=5)
        except Exception as e:
            logger.debug(f"GET request error ({param}): {e}")
            continue

        success_indicator = check_for_success_indicator(response.text)
        error_indicator = check_for_error_indicator(response.text)

        if success_indicator:
            vulnerabilities.append(
                _create_finding(
                    "SQL Injection (Data Retrieval/Boolean)",
                    Severity.HIGH,
                    full_url,
                    success_payload,
                    "GET",
                    param,
                    f"성공 징후 '{success_indicator}' 발견",
                )
            )
            continue

        if error_indicator:
            vulnerabilities.append(
                _create_finding(
                    "SQL Injection (Error Based)",
                    Severity.HIGH,
                    full_url,
                    success_payload,
                    "GET",
                    param,
                    f"에러 키워드 '{error_indicator}' 발견",
                )
            )
            continue

        # 2. Time based blind detection
        attack_url_time = f"{base_url}?{param}=1{TEST_PAYLOAD_TIME_BLIND}"
        try:
            start_time = time.time()
            client.get(attack_url_time, timeout=10)
            elapsed_time = time.time() - start_time

            if elapsed_time > TIME_THRESHOLD:
                vulnerabilities.append(
                    _create_finding(
                        "SQL Injection (Time Based)",
                        Severity.MEDIUM,
                        full_url,
                        TEST_PAYLOAD_TIME_BLIND,
                        "GET",
                        param,
                        f"응답 시간 {elapsed_time:.2f}초 초과",
                    )
                )
        except Exception as e:
            logger.debug(f"GET (Time Blind) request error ({param}): {e}")
            pass

    return vulnerabilities


def _scan_forms(client: HttpClient, url: str) -> List[Finding]:
    vulnerabilities = []

    try:
        response = client.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
    except Exception as e:
        logger.debug(f"Form page request error: {e}")
        return []

    for form in forms:
        method = form.get("method", "GET").upper()
        form_url = requests.compat.urljoin(url, form.get("action", url))
        input_fields = form.find_all(["input", "textarea", "select"])
        param_names = [field.get("name") for field in input_fields if field.get("name")]

        if not param_names:
            continue

        for param in param_names:
            # 1. Error based detection
            test_data_error = {
                p: f"1{TEST_PAYLOAD}" if p == param else "1" for p in param_names
            }

            # HttpClient wrapper uses .post(url, data=...) and .get(url, params=...)
            # Note: HttpClient.get signature is (url, **kwargs), so params should be passed in kwargs

            try:
                if method == "POST":
                    res = client.post(
                        form_url, data=test_data_error, timeout=5, allow_redirects=True
                    )
                else:
                    res = client.get(
                        form_url,
                        params=test_data_error,
                        timeout=5,
                        allow_redirects=True,
                    )
            except Exception as e:
                logger.debug(f"Form request error ({method}/{param}): {e}")
                continue

            error_indicator = check_for_error_indicator(res.text)
            if error_indicator:
                vulnerabilities.append(
                    _create_finding(
                        "SQL Injection (Error Based)",
                        Severity.HIGH,
                        form_url,
                        f"1{TEST_PAYLOAD}",
                        method,
                        param,
                        f"에러 키워드 '{error_indicator}' 발견",
                    )
                )
                continue

            # 2. Time based blind detection
            test_data_time = {
                p: f"1{TEST_PAYLOAD_TIME_BLIND}" if p == param else "1"
                for p in param_names
            }
            try:
                start_time = time.time()
                if method == "POST":
                    client.post(
                        form_url, data=test_data_time, timeout=10, allow_redirects=True
                    )
                else:
                    client.get(
                        form_url,
                        params=test_data_time,
                        timeout=10,
                        allow_redirects=True,
                    )

                elapsed_time = time.time() - start_time

                if elapsed_time > TIME_THRESHOLD:
                    vulnerabilities.append(
                        _create_finding(
                            "SQL Injection (Time Based)",
                            Severity.MEDIUM,
                            form_url,
                            TEST_PAYLOAD_TIME_BLIND,
                            method,
                            param,
                            f"응답 시간 {elapsed_time:.2f}초 초과",
                        )
                    )
            except Exception as e:
                logger.debug(f"Form (Time Blind) request error ({method}/{param}): {e}")
                pass

    return vulnerabilities
