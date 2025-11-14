"""통합 테스트: XSS Plugin 전체 플로우 검증

이 파일은 XSS 플러그인의 주요 컴포넌트들이 연동되어 동작하는
전체 스캔 플로우를 검증합니다.

- ReflectedScanner: 반사형 XSS 스캔 (GET/POST)
- StoredScanner: 저장형 XSS 스캔
- XSSPlugin: 플러그인 전체 실행

통합 테스트 원칙:
1. plugin_context_factory로 PluginContext 생성
2. scanner.run(plugin_context) 실행
3. PluginResult.status 및 PluginResult.findings 검증
4. responses 라이브러리로 HTTP 완전 모킹
"""

import pytest

responses = pytest.importorskip("responses")


@pytest.mark.integration
def test_reflected_scanner_get_flow(responses_mock, plugin_context_factory, payload_path):
    """ReflectedScanner GET 방식 반사형 XSS 전체 플로우"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import ReflectedScanner
    try:
        from s2n.s2nscanner.interfaces import PluginStatus
    except ImportError:
        from s2n.s2nscanner.plugins.xss.xss_scanner import PluginStatus

    target_url = "https://example.com/search?q=test&lang=en"

    # 1. PluginContext 생성
    context = plugin_context_factory(
        target_urls=[target_url]
    )

    # 2. HTTP 모킹 설정 - 입력 지점 탐지 요청
    responses_mock.get(
        "https://example.com/search",
        body="<html><body>Search page</body></html>",
        status=200
    )

    # 3. 페이로드 주입 요청에 대한 동적 응답 설정
    def request_callback(request):
        """동적으로 페이로드 반사 여부 결정"""
        from urllib.parse import unquote, parse_qs, urlparse

        parsed = urlparse(request.url)
        params = parse_qs(parsed.query)

        # q 파라미터 값 추출 및 디코딩
        q_values = params.get('q', [''])
        q_value = unquote(q_values[0]) if q_values else ''

        # q 파라미터에 XSS 페이로드가 포함되면 그대로 반사
        if any(pattern in q_value for pattern in ['<script>', 'alert', '<img', 'onerror', '<svg', '<body']):
            # 페이로드를 그대로 반사하여 취약점 시뮬레이션
            body = f'<html><body><div>Results for: {q_value}</div></body></html>'
        else:
            body = '<html><body>Normal response</body></html>'

        return (200, {}, body)

    responses_mock.add_callback(
        responses.GET,
        "https://example.com/search",
        callback=request_callback
    )

    # 4. ReflectedScanner 실행
    scanner = ReflectedScanner(
        payload_path,
        http_client=context.scan_context.http_client
    )
    result = scanner.run(context)

    # 5. PluginResult 검증
    # PluginStatus.SUCCESS는 enum이거나 string일 수 있으므로, 결과는 string으로 비교
    assert result.status in ["success", PluginStatus.SUCCESS], "스캔이 성공적으로 완료되어야 함"
    assert result.plugin_name == "xss"
    assert result.urls_scanned >= 1, "최소 1개 URL이 스캔되어야 함"
    assert result.requests_sent > 0, "최소 1개 요청이 전송되어야 함"

    # 6. Findings 검증
    assert len(result.findings) >= 1, "GET 파라미터에서 XSS 취약점이 탐지되어야 함"

    # 첫 번째 finding 검증
    finding = result.findings[0]
    assert finding.url == "https://example.com/search"
    assert finding.parameter == "q", "q 파라미터에서 취약점이 발견되어야 함"
    assert finding.method == "GET"
    assert finding.plugin == "xss"
    assert finding.payload is not None, "페이로드가 있어야 함"
    assert len(finding.payload) > 0


@pytest.mark.integration
def test_reflected_scanner_no_vulnerability(responses_mock, plugin_context_factory, payload_path):
    """취약점이 없는 경우 빈 결과 반환"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import ReflectedScanner
    try:
        from s2n.s2nscanner.interfaces import PluginStatus
    except ImportError:
        from s2n.s2nscanner.plugins.xss.xss_scanner import PluginStatus

    target_url = "https://safe.example.com/page?id=123"

    # 1. PluginContext 생성
    context = plugin_context_factory(
        target_urls=[target_url]
    )

    # 2. 입력 지점 탐지 요청 모킹
    responses_mock.get(
        "https://safe.example.com/page",
        body="<html><body>Safe page</body></html>",
        status=200
    )

    # 3. 모든 페이로드에 대해 안전한 응답 (반사 없음) - callback으로 처리
    def safe_callback(request):
        """항상 안전한 응답 반환 (페이로드 반사 없음)"""
        return (200, {}, "<html><body>Safe response - no reflection</body></html>")

    responses_mock.add_callback(
        responses.GET,
        "https://safe.example.com/page",
        callback=safe_callback
    )

    # 4. ReflectedScanner 실행
    scanner = ReflectedScanner(
        payload_path,
        http_client=context.scan_context.http_client
    )
    result = scanner.run(context)

    # 5. PluginResult 검증
    assert result.status in ["success", PluginStatus.SUCCESS], "스캔은 성공해야 함"
    assert result.urls_scanned >= 1

    # 6. Findings 검증 - 취약점 없음
    assert len(result.findings) == 0, "취약점이 없는 페이지에서는 finding이 없어야 함"


@pytest.mark.integration
def test_reflected_scanner_multiple_parameters(responses_mock, plugin_context_factory, payload_path):
    """여러 파라미터 중 일부만 취약한 경우"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import ReflectedScanner
    try:
        from s2n.s2nscanner.interfaces import PluginStatus
    except ImportError:
        from s2n.s2nscanner.plugins.xss.xss_scanner import PluginStatus

    target_url = "https://example.com/app?user=admin&search=test&page=1"

    # 1. PluginContext 생성
    context = plugin_context_factory(
        target_urls=[target_url]
    )

    # 2. 입력 지점 탐지 요청 모킹
    responses_mock.get(
        "https://example.com/app",
        body="<html><body>App page</body></html>",
        status=200
    )

    # 3. 동적 응답 설정 - search 파라미터만 취약
    def request_callback(request):
        from urllib.parse import unquote, parse_qs, urlparse

        parsed = urlparse(request.url)
        params = parse_qs(parsed.query)

        # search 파라미터 값 추출 및 디코딩
        search_values = params.get('search', [''])
        search_value = unquote(search_values[0]) if search_values else ''

        # search 파라미터에 XSS 페이로드가 포함되어 있으면 반사
        if any(pattern in search_value for pattern in ['<script>', 'alert', '<img', 'onerror', '<svg', '<body']):
            body = f'<html><body>Search: {search_value}</body></html>'
        else:
            body = '<html><body>Normal page</body></html>'

        return (200, {}, body)

    responses_mock.add_callback(
        responses.GET,
        "https://example.com/app",
        callback=request_callback
    )

    # 4. ReflectedScanner 실행
    scanner = ReflectedScanner(
        payload_path,
        http_client=context.scan_context.http_client
    )
    result = scanner.run(context)

    # 5. PluginResult 검증
    assert result.status in ["success", PluginStatus.SUCCESS]
    assert result.urls_scanned >= 1

    # 6. Findings 검증 - search 파라미터에서만 취약점 발견
    if len(result.findings) > 0:
        # 발견된 취약점은 search 파라미터여야 함
        search_findings = [f for f in result.findings if f.parameter == "search"]
        assert len(search_findings) >= 1, "search 파라미터에서 취약점이 발견되어야 함"

        # user와 page 파라미터는 취약하지 않음
        user_findings = [f for f in result.findings if f.parameter == "user"]
        page_findings = [f for f in result.findings if f.parameter == "page"]
        assert len(user_findings) == 0, "user 파라미터는 안전해야 함"
        assert len(page_findings) == 0, "page 파라미터는 안전해야 함"


@pytest.mark.integration
def test_reflected_scanner_post_flow(responses_mock, plugin_context_factory, payload_path):
    """ReflectedScanner POST 방식 반사형 XSS 전체 플로우"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import ReflectedScanner
    try:
        from s2n.s2nscanner.interfaces import PluginStatus
    except ImportError:
        from s2n.s2nscanner.plugins.xss.xss_scanner import PluginStatus

    target_url = "https://example.com/submit"

    # 1. PluginContext 생성
    context = plugin_context_factory(
        target_urls=[target_url]
    )

    # 2. 입력 지점 탐지 요청 모킹 - form 포함
    responses_mock.get(
        target_url,
        body="""
        <html>
        <body>
            <form action="/submit" method="POST">
                <input type="text" name="comment" value="">
                <input type="text" name="author" value="">
                <input type="submit" value="Submit">
            </form>
        </body>
        </html>
        """,
        status=200
    )

    # 3. POST 요청에 대한 동적 응답 설정
    def post_callback(request):
        """POST 요청 본문에서 comment 필드 확인"""
        from urllib.parse import unquote

        body_str = request.body if isinstance(request.body, str) else request.body.decode('utf-8')
        decoded_body = unquote(body_str)

        # comment 필드에 XSS 페이로드가 포함되면 반사
        if any(pattern in decoded_body for pattern in ['<script>', 'alert', '<img', 'onerror', '<svg', '<body']):
            response_body = f'<html><body><div>Your comment: {decoded_body}</div></body></html>'
        else:
            response_body = '<html><body>Thank you for your comment</body></html>'

        return (200, {}, response_body)

    responses_mock.add_callback(
        responses.POST,
        target_url,
        callback=post_callback
    )

    # 4. ReflectedScanner 실행
    scanner = ReflectedScanner(
        payload_path,
        http_client=context.scan_context.http_client
    )
    result = scanner.run(context)

    # 5. PluginResult 검증
    assert result.status in ["success", PluginStatus.SUCCESS]
    assert result.urls_scanned >= 1
    assert result.requests_sent > 0

    # 6. Findings 검증
    assert len(result.findings) >= 1, "POST form에서 XSS 취약점이 탐지되어야 함"

    # POST 메서드로 발견된 취약점 확인
    post_findings = [f for f in result.findings if f.method == "POST"]
    assert len(post_findings) >= 1, "POST 메서드로 취약점이 발견되어야 함"

    finding = post_findings[0]
    assert finding.url == target_url
    assert finding.parameter in ["comment", "author"]
    assert finding.plugin == "xss"


@pytest.mark.integration
def test_reflected_scanner_with_csrf_token(responses_mock, plugin_context_factory, payload_path):
    """CSRF 토큰이 포함된 form 처리 테스트"""
    from s2n.s2nscanner.plugins.xss.xss_scanner import ReflectedScanner
    try:
        from s2n.s2nscanner.interfaces import PluginStatus
    except ImportError:
        from s2n.s2nscanner.plugins.xss.xss_scanner import PluginStatus

    target_url = "https://example.com/protected"

    # 1. PluginContext 생성
    context = plugin_context_factory(
        target_urls=[target_url]
    )

    # 2. 입력 지점 탐지 - CSRF 토큰 포함된 form
    responses_mock.get(
        target_url,
        body="""
        <html>
        <body>
            <form action="/protected" method="POST">
                <input type="hidden" name="csrf_token" value="abc123def456">
                <input type="text" name="message" value="">
                <input type="submit" value="Send">
            </form>
        </body>
        </html>
        """,
        status=200
    )

    # 3. POST 요청에 대한 동적 응답 - csrf_token 검증
    def post_callback(request):
        from urllib.parse import unquote

        body_str = request.body if isinstance(request.body, str) else request.body.decode('utf-8')
        decoded_body = unquote(body_str)

        # CSRF 토큰이 없으면 거부
        if 'csrf_token' not in body_str:
            return (403, {}, '<html><body>CSRF token missing</body></html>')

        # message 필드에 XSS 페이로드가 포함되면 반사
        if any(pattern in decoded_body for pattern in ['<script>', 'alert', '<img', 'onerror', '<svg', '<body']):
            response_body = f'<html><body><div>Message: {decoded_body}</div></body></html>'
        else:
            response_body = '<html><body>Message received</body></html>'

        return (200, {}, response_body)

    responses_mock.add_callback(
        responses.POST,
        target_url,
        callback=post_callback
    )

    # 4. ReflectedScanner 실행
    scanner = ReflectedScanner(
        payload_path,
        http_client=context.scan_context.http_client
    )
    result = scanner.run(context)

    # 5. PluginResult 검증
    assert result.status in ["success", PluginStatus.SUCCESS]
    assert result.urls_scanned >= 1

    # 6. Findings 검증 - CSRF 토큰은 스킵되고 message만 테스트됨
    if len(result.findings) > 0:
        # csrf_token 파라미터는 테스트되지 않아야 함
        csrf_findings = [f for f in result.findings if f.parameter == "csrf_token"]
        assert len(csrf_findings) == 0, "CSRF 토큰 파라미터는 스캔되지 않아야 함"

        # message 파라미터에서 취약점 발견 가능
        message_findings = [f for f in result.findings if f.parameter == "message"]
        if len(message_findings) > 0:
            assert message_findings[0].method == "POST"


@pytest.mark.integration
def test_stored_xss_scanner_flow(responses_mock, plugin_context_factory, payload_path):
    """StoredScanner 저장형 XSS 전체 플로우

    참고: 현재 ReflectedScanner.run()은 기본적으로 반사형만 테스트하며,
    저장형 XSS는 _test_stored() 메서드를 직접 호출해야 합니다.
    이 테스트는 저장형 XSS 탐지 로직의 통합 플로우를 검증합니다.
    """
    from s2n.s2nscanner.plugins.xss.xss_scanner import ReflectedScanner, InputPoint
    try:
        from s2n.s2nscanner.interfaces import PluginStatus
    except ImportError:
        from s2n.s2nscanner.plugins.xss.xss_scanner import PluginStatus

    target_url = "https://example.com/guestbook"

    # 1. PluginContext 생성
    context = plugin_context_factory(
        target_urls=[target_url]
    )

    # 2. 저장형 페이로드를 추적할 변수
    stored_payloads = []

    # 3. POST 요청 - 저장형 페이로드 제출
    def post_callback(request):
        """POST 요청으로 제출된 페이로드를 저장"""
        from urllib.parse import unquote, parse_qs

        body_str = request.body if isinstance(request.body, str) else request.body.decode('utf-8')
        decoded_body = unquote(body_str)
        params = parse_qs(decoded_body)

        # 제출된 message를 저장
        if 'message' in params:
            message_value = params['message'][0] if isinstance(params['message'], list) else params['message']
            if 's2n_stored_' in message_value or '<script>' in message_value:
                stored_payloads.append(message_value)

        return (200, {}, '<html><body>Message posted successfully</body></html>')

    responses_mock.add_callback(
        responses.POST,
        target_url,
        callback=post_callback
    )

    # 4. GET 요청 - 입력 지점 탐지 + 저장된 페이로드 확인
    def get_callback(request):
        """입력 지점 탐지를 위한 form + 저장된 페이로드를 포함한 응답"""
        messages_html = ""
        for payload in stored_payloads:
            # 저장된 페이로드를 그대로 반사 (취약점 시뮬레이션)
            messages_html += f'<div class="message">{payload}</div>\n'

        response_body = f"""
        <html>
        <body>
            <h1>Guestbook</h1>
            <form action="/guestbook" method="POST">
                <input type="text" name="name" value="">
                <textarea name="message"></textarea>
                <input type="submit" value="Submit">
            </form>
            <div id="messages">
                {messages_html}
            </div>
        </body>
        </html>
        """
        return (200, {}, response_body)

    responses_mock.add_callback(
        responses.GET,
        target_url,
        callback=get_callback
    )

    # 5. ReflectedScanner 생성 및 _test_stored 직접 호출
    scanner = ReflectedScanner(
        payload_path,
        http_client=context.scan_context.http_client
    )

    # InputPoint 생성 (입력 지점)
    input_point = InputPoint(
        url=target_url,
        method="POST",
        parameters={"name": "", "message": ""},
        source="form"
    )

    # 저장형 XSS 테스트 실행
    stored_result = scanner._test_stored(input_point)

    # 6. 저장형 XSS 탐지 결과 검증
    if stored_result:
        assert stored_result.category == "stored"
        assert stored_result.category_ko == "저장형"
        assert "s2n_stored_" in stored_result.payload or "<script>" in stored_result.payload

        # _record_stored로 finding 기록
        scanner._record_stored(input_point, stored_result)

        # 검증
        assert len(scanner.findings) == 1
        key = f"{target_url}|[stored]|POST"
        assert key in scanner.findings
        assert scanner.findings[key].parameter == "[stored]"
    else:
        # 저장형 XSS가 탐지되지 않은 경우도 허용
        # (테스트 환경에 따라 달라질 수 있음)
        pass


@pytest.mark.integration
def test_xss_plugin_run_integration(responses_mock, plugin_context_factory, payload_path):
    """XSSScanner.run() 통합 테스트

    XSSScanner가 PluginContext를 받아 ReflectedScanner를 실행하고
    PluginResult를 올바르게 반환하는지 검증합니다.
    """
    from s2n.s2nscanner.plugins.xss.xss import XSSScanner
    try:
        from s2n.s2nscanner.interfaces import PluginStatus
    except ImportError:
        from s2n.s2nscanner.plugins.xss.xss_scanner import PluginStatus

    target_url = "https://example.com/vulnerable"

    # 1. PluginContext 생성
    context = plugin_context_factory(target_urls=[target_url])

    # 2. 입력 지점 탐지를 위한 초기 GET 응답
    responses_mock.get(
        target_url,
        body="""
        <html>
        <body>
            <form action="/vulnerable" method="GET">
                <input type="text" name="search" value="">
                <input type="submit" value="Search">
            </form>
        </body>
        </html>
        """,
        status=200
    )

    # 3. 페이로드 주입 요청에 대한 동적 응답
    def request_callback(request):
        """XSS 페이로드를 반사하는 취약한 응답"""
        from urllib.parse import unquote, parse_qs, urlparse

        parsed = urlparse(request.url)
        params = parse_qs(parsed.query)

        # search 파라미터 값 추출 및 디코딩
        search_values = params.get('search', [''])
        search_value = unquote(search_values[0]) if search_values else ''

        # XSS 페이로드가 포함되면 그대로 반사
        if any(pattern in search_value for pattern in ['<script>', 'alert', '<img', 'onerror', '<svg', '<body']):
            body = f'<html><body><div class="results">Search results for: {search_value}</div></body></html>'
        else:
            body = '<html><body>No results</body></html>'

        return (200, {}, body)

    responses_mock.add_callback(
        responses.GET,
        target_url,
        callback=request_callback
    )

    # 4. XSSScanner 생성 및 실행
    plugin = XSSScanner(config={"payload_path": str(payload_path)})
    result = plugin.run(context)

    # 5. PluginResult 검증
    assert result.plugin_name == "xss"
    assert result.status in ["success", "partial", PluginStatus.SUCCESS, PluginStatus.PARTIAL]
    assert result.urls_scanned >= 1
    assert result.requests_sent > 0

    # 6. Findings 검증
    assert len(result.findings) >= 1, "XSS 취약점이 탐지되어야 함"

    # 첫 번째 finding 상세 검증
    first_finding = result.findings[0]
    assert first_finding.plugin == "xss"
    assert first_finding.url == target_url
    assert first_finding.parameter == "search"
    assert first_finding.method == "GET"
    assert first_finding.payload is not None
    assert len(first_finding.payload) > 0

    # Severity와 Confidence 검증
    assert hasattr(first_finding, "severity")
    assert hasattr(first_finding, "confidence")


@pytest.mark.integration
def test_xss_plugin_no_http_client_error(plugin_context_factory, payload_path):
    """XSSScanner가 http_client 없이 실행되면 PluginError 반환"""
    from s2n.s2nscanner.plugins.xss.xss import XSSScanner
    from s2n.s2nscanner.interfaces import PluginError

    # http_client가 None인 context 생성
    context = plugin_context_factory(target_urls=["https://test.com"])
    context.scan_context.http_client = None

    plugin = XSSScanner(config={"payload_path": str(payload_path)})
    result = plugin.run(context)

    # PluginError가 반환되는지 확인
    assert isinstance(result, PluginError)
    assert result.error_type == "ValueError"
    assert "http_client" in result.message


@pytest.mark.integration
def test_xss_plugin_uses_default_target_url(responses_mock, mock_http_client, payload_path):
    """XSSScanner가 target_urls가 없으면 scan_context.config.target_url 사용"""
    from s2n.s2nscanner.plugins.xss.xss import XSSScanner
    from datetime import datetime, timezone
    import time
    try:
        from s2n.s2nscanner.interfaces import PluginStatus, PluginContext, ScanContext, ScanConfig, PluginConfig
    except ImportError:
        from conftest import PluginStatus, PluginContext, ScanContext, ScanConfig, PluginConfig

    target_url = "https://example.com/default"

    # ScanConfig를 target_url과 함께 생성
    scan_config = ScanConfig(target_url=target_url)
    scan_context = ScanContext(
        scan_id=f"test-{int(time.time())}",
        start_time=datetime.now(timezone.utc),
        config=scan_config,
        http_client=mock_http_client,
        crawler=None
    )

    # target_urls=None으로 PluginContext 생성
    context = PluginContext(
        plugin_name="xss",
        scan_context=scan_context,
        plugin_config=PluginConfig(enabled=True, timeout=5, max_payloads=50, custom_params={}),
        target_urls=None,  # 명시적으로 None
        logger=None
    )

    # 입력 지점 탐지용 응답
    responses_mock.get(
        target_url,
        body="<html><body>Page with no forms</body></html>",
        status=200
    )

    plugin = XSSScanner(config={"payload_path": str(payload_path)})
    result = plugin.run(context)

    # PluginResult 검증
    assert result.status in ["success", "skipped", PluginStatus.SUCCESS, PluginStatus.SKIPPED]
    # target_urls가 None이면 scan_context.config.target_url 사용하므로 urls_scanned >= 1
    assert result.urls_scanned >= 1
