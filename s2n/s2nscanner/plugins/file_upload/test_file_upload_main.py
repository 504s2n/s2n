import sys
import os
import unittest
from unittest.mock import MagicMock, patch, mock_open

# Add the project root to the Python path to resolve import errors
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
sys.path.insert(0, project_root)

from datetime import datetime
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from s2n.s2nscanner.interfaces import (
    Finding,
    PluginContext,
    PluginResult,
    PluginStatus,
    Severity,
    ScanContext,
    ScannerConfig, # Config를 제거하고 ScannerConfig가 Config 역할을 대체
)

from s2n.s2nscanner.plugins.file_upload.file_upload_main import FileUploadPlugin

class TestFileUploadPlugin(unittest.TestCase):
    def setUp(self):
        """각 테스트에 대한 모의(mock) 컨텍스트를 설정합니다."""
        self.mock_http_client = MagicMock()

        mock_scanner_config = ScannerConfig(crawl_depth=2)
        
        # 1. Config 객체 생성 라인 (mock_config = Config(...))을 삭제합니다.
        
        # 2. ScanContext가 필요한 인수를 직접 받도록 변경합니다.
        mock_scan_context = ScanContext(
            target_url="http://test.com",         # target_url을 ScanContext에 직접 전달
            scanner_config=mock_scanner_config,   # scanner_config를 ScanContext에 직접 전달
            http_client=self.mock_http_client
        )
        self.plugin_context = PluginContext(scan_context=mock_scan_context)
        self.plugin = FileUploadPlugin()

    def _mock_response(self, text, status_code=200, headers=None):
        """모의(mock) 응답 객체를 생성하는 헬퍼 함수입니다."""
        response = MagicMock()
        response.text = text
        response.status_code = status_code
        response.headers = headers or {}
        # 필요한 경우 guess_uploaded_urls를 위해 응답을 순회 가능하게 만듭니다
        response.iter_lines.return_value = text.splitlines()
        # 소비자가 접근할 수 있는 url 속성을 추가합니다
        response.url = "http://test.com/upload"
        return response

    def test_run_finds_vulnerability_on_first_page(self):
        """초기 대상 URL에서 취약점을 찾는 것을 테스트합니다."""
        # 준비
        upload_form_html = """
        <html><body>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="file" name="upload" />
                <input type="submit" value="Upload" />
            </form>
        </body></html>
        """
        success_page_html = "파일이 성공적으로 업로드되었습니다."
        vuln_page_html = '<?php echo "File Upload Test"; ?>'
        
        # 응답 모의 처리
        self.mock_http_client.get.side_effect = [
            self._mock_response(upload_form_html),  # 초기 페이지 가져오기
            self._mock_response(vuln_page_html)      # 업로드된 파일 검증
        ]
        self.mock_http_client.post.return_value = self._mock_response(success_page_html)

        # 실행
        with patch("s2n.s2nscanner.plugins.file_upload.file_upload_main.guess_uploaded_urls", return_value=["http://test.com/uploads/test.php"]):
            result = self.plugin.run(self.plugin_context)

        # 단언
        self.assertEqual(result.status, PluginStatus.SUCCESS)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertIn("파일 업로드 취약점 발견", finding.title)
        self.mock_http_client.post.assert_called_once()
        # 초기 GET + 검증 GET
        self.assertEqual(self.mock_http_client.get.call_count, 2)

    def test_run_no_form_found(self):
        """전체 DFS 스캔 후에도 업로드 폼을 찾지 못하는 경우를 테스트합니다."""
        # 준비
        no_form_html = "<html><body><p>그냥 텍스트입니다.</p><a href='/page2'></a></body></html>"
        page2_html = "<html><body><p>여전히 아무것도 없습니다.</p></body></html>"
        self.mock_http_client.get.side_effect = [
            self._mock_response(no_form_html),
            self._mock_response(page2_html)
        ]

        # 실행
        result = self.plugin.run(self.plugin_context)

        # 단언
        self.assertEqual(result.status, PluginStatus.SUCCESS)
        self.assertEqual(len(result.findings), 0)
        self.assertEqual(result.urls_scanned, 2)

    def test_run_potential_vulnerability(self):
        """잠재적 취약점 발견을 테스트합니다 (업로드 성공했으나 파일은 찾지 못함)."""
        # 준비
        upload_form_html = """
        <html><body>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="file" name="upload" />
                <input type="submit" value="Upload" />
            </form>
        </body></html>
        """
        success_page_html = "파일이 성공적으로 업로드되었습니다."
        
        self.mock_http_client.get.return_value = self._mock_response(upload_form_html)
        self.mock_http_client.post.return_value = self._mock_response(success_page_html)

        # 실행
        with patch("s2n.s2nscanner.plugins.file_upload.file_upload_main.guess_uploaded_urls", return_value=["http://test.com/uploads/test.php"]):
            # 검증 GET 요청이 실패하도록 만듭니다
            self.mock_http_client.get.side_effect = [
                self._mock_response(upload_form_html),
                self._mock_response("Not Found", 404)
            ]
            result = self.plugin.run(self.plugin_context)

        # 단언
        self.assertEqual(result.status, PluginStatus.SUCCESS)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertIn("잠재적인 파일 업로드 취약점", finding.title)

    def test_run_finds_form_with_dfs(self):
        """DFS를 통해 연결된 페이지에서 업로드 폼을 찾는 것을 테스트합니다."""
        # 준비
        main_page_html = "<html><body><a href='/upload_page'>업로드로 이동</a></body></html>"
        upload_form_html = """
        <html><body>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <input type="file" name="upload" />
                <input type="submit" value="Upload" />
            </form>
        </body></html>
        """
        vuln_page_html = '<?php echo "File Upload Test"; ?>'
        
        self.mock_http_client.get.side_effect = [
            self._mock_response(main_page_html),      # 메인 페이지
            self._mock_response(upload_form_html),    # DFS가 이 페이지를 찾음
            self._mock_response(vuln_page_html)       # 검증
        ]
        self.mock_http_client.post.return_value = self._mock_response("성공")

        # 실행
        with patch("s2n.s2nscanner.plugins.file_upload.file_upload_main.guess_uploaded_urls", return_value=["http://test.com/uploads/test.php"]):
            result = self.plugin.run(self.plugin_context)

        # 단언
        self.assertEqual(result.status, PluginStatus.SUCCESS)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, Severity.HIGH)
        self.assertEqual(self.mock_http_client.get.call_count, 3)

    def test_run_skips_login_page(self):
        """플러그인이 로그인 페이지로 보이는 페이지를 건너뛰는지 테스트합니다."""
        # 준비
        login_page_html = """
        <html><body>
            <form action="/login" method="post">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <input type="submit" value="Login" />
            </form>
        </body></html>
        """
        self.mock_http_client.get.return_value = self._mock_response(login_page_html)

        # 실행
        result = self.plugin.run(self.plugin_context)

        # 단언
        self.assertEqual(result.status, PluginStatus.SKIPPED)
        self.assertEqual(len(result.findings), 0)

    def test_run_handles_http_error(self):
        """HTTP 오류 발생 시 플러그인이 정상적으로 실패하는지 테스트합니다."""
        # 준비
        self.mock_http_client.get.side_effect = Exception("연결 시간 초과")

        # 실행
        result = self.plugin.run(self.plugin_context)

        # 단언
        self.assertEqual(result.status, PluginStatus.FAILED)
        self.assertIsNotNone(result.error)
        self.assertEqual(result.error.error_type, "Exception")
        self.assertEqual(result.error.message, "연결 시간 초과")

    def test_run_with_csrf_token(self):
        """CSRF 토큰이 있는 폼에서 취약점을 찾는 것을 테스트합니다."""
        # 준비
        csrf_token = "abcde12345"
        upload_form_html = f"""
        <html><body>
            <form action="/upload_with_csrf" method="post" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="{csrf_token}" />
                <input type="file" name="upload" />
                <input type="submit" value="Upload" />
            </form>
        </body></html>
        """
        success_page_html = "파일이 성공적으로 업로드되었습니다."
        vuln_page_html = '<?php echo "File Upload Test"; ?>'

        # 응답 모의 처리
        self.mock_http_client.get.side_effect = [
            self._mock_response(upload_form_html),  # 초기 페이지
            self._mock_response(vuln_page_html)      # 검증
        ]
        self.mock_http_client.post.return_value = self._mock_response(success_page_html)

        # 실행
        with patch("s2n.s2nscanner.plugins.file_upload.file_upload_main.guess_uploaded_urls", return_value=["http://test.com/uploads/test.php"]):
            result = self.plugin.run(self.plugin_context)

        # 단언
        self.assertEqual(result.status, PluginStatus.SUCCESS)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, Severity.HIGH)

        # POST 요청에 CSRF 토큰이 포함되었는지 확인
        self.mock_http_client.post.assert_called_once()
        args, kwargs = self.mock_http_client.post.call_args
        self.assertIn('data', kwargs)
        # collect_form_data가 CSRF 토큰을 수집했다고 가정합니다.
        self.assertIn('csrf_token', kwargs['data'])
        self.assertEqual(kwargs['data']['csrf_token'], csrf_token)

if __name__ == "__main__":
    unittest.main()
