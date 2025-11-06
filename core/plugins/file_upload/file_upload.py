# 메인 클래스 (FileUploadVulnerability)
#참고 명령어: full_url = input("테스트할  취약점 페이지 전체 URL을 입력하세요 : ").strip()


import requests  # HTTP 요청/세션 관리 라이브러리
from bs4 import BeautifulSoup  # HTML을 파싱해 DOM 탐색을 쉽게 해주는 라이브러리
import os  # 파일 경로/존재 확인 등 운영체제 관련 기능
import tempfile  # 임시 파일/디렉터리 생성 유틸리티
import uuid  # 고유한 파일명 생성을 위한 UUID 생성기
import re  # 정규식으로 텍스트에서 패턴 검색/추출
from urllib.parse import urljoin, urlparse  # URL 결합(urljoin)과 분해(urlparse)
from collections import deque  # BFS(너비 우선 탐색)에 사용하는 큐 자료구조

# 헬퍼 함수 임포트: 패키지 실행/모듈 실행/직접 실행 모두 지원
try:
    from .file_upload_functions import (  # 패키지 컨텍스트에서의 상대 임포트
        find_upload_form,
        collect_form_data,
        find_login_form,
        perform_login,
        guess_uploaded_urls,
    )
except Exception:
    try:
        # 프로젝트 루트 기준 패키지 절대 임포트
        from core.plugins.file_upload.file_upload_functions import (
            find_upload_form,
            collect_form_data,
            find_login_form,
            perform_login,
            guess_uploaded_urls,
        )
    except Exception:
        # 스크립트를 직접 실행한 경우: 현재 파일 디렉터리를 경로에 추가 후 로컬 임포트
        import os as _os, sys as _sys
        _sys.path.append(_os.path.dirname(__file__))
        from file_upload_functions import (
            find_upload_form,
            collect_form_data,
            find_login_form,
            perform_login,
            guess_uploaded_urls,
        )

# 이 모듈은 "파일 업로드 취약점"을 자동으로 확인하는 스캐너를 제공합니다.
# - 주어진 페이지에서 파일 업로드 폼을 찾고
# - 테스트용 파일을 업로드 시도하며
# - 업로드가 성공했는지 다양한 방법으로 추정합니다.

class FileUploadVulnerability:
   
    #범용 파일 업로드 취약점 검사기
    # - 업로드 폼 존재 여부 확인
    # - CSRF/hidden inputs 처리 시도
    # - 테스트 파일 업로드 시도 및 업로드 위치 추측
   

    def __init__(self, upload_page_url, session=None):
        # upload_page_url: 테스트할 파일 업로드 취약점 페이지 URL
        # session: requests.Session 객체 (기본값: None, 새 세션 생성)
        self.upload_page_url = upload_page_url
        self.session = session or requests.Session()

    # helper functions moved to file_upload.functions module

    def test_file_upload(self):
        # 페이지 로드
        print(f"[*] Fetching upload page: {self.upload_page_url}")
        try:
            resp = self.session.get(self.upload_page_url, timeout=10)
        except Exception as e:
            return {'vulnerable': False, 'message': f'Failed to fetch page: {e}'}

        # 인증/쿠키 필요 여부 빠른 점검
        try:
            final_url = (resp.url or "").lower()
            body_lower = resp.text.lower()
        except Exception:
            final_url = ""
            body_lower = ""
        if resp.status_code in (401, 403) or "login" in final_url or ("login" in body_lower and "password" in body_lower):
            return {'vulnerable': False, 'message': '쿠키 값 또는 로그인이 필요한 페이지입니다. 접근 불가로 취약점 확인 불가.'}

        soup = BeautifulSoup(resp.text, 'html.parser')
        # soup: HTML 파싱 결과 (페이지의 DOM 구조를 다루기 쉽게 만들어 줌)
        form = find_upload_form(soup)
        # form: <input type="file">를 포함하는 첫 번째 <form> 요소 (없으면 None)
        found_at = self.upload_page_url
        # found_at: 해당 form이 실제로 발견된 페이지 URL (링크 타고 이동 중 발견될 수 있어 기록)

        # 로그인 폼이 감지되면 별도의 로그인 플러그인에서 처리해야 하므로
        # 이 페이지 자체에 업로드 폼이 있는지 여부만 판단합니다.
        if form is None:
            login_form = find_login_form(soup)
            if login_form is not None:
                # 로그인 페이지로 판단됨 — 로그인 없이 이 페이지에서 업로드 폼이 없으므로 취약점 없음으로 간주
                return {'vulnerable': False, 'message': 'Page requires login; no upload form found on this login page.'}

        # 추가 탐색: 파일 input이 폼 바깥에 존재하는 경우, data-* 혹은 onclick 등에 upload 관련 엔드포인트가 있을 수 있음
        candidate_urls = set()
        # candidate_urls: 페이지 내 스크립트/속성에서 추출한 업로드 관련 후보 엔드포인트 모음
        parsed_root = urlparse(self.upload_page_url)
        # parsed_root: 스킴/호스트 등을 분리해 동일 호스트 탐색(BFS)에 활용

        # 1) file input이 폼 바깥에 있는지 체크
        if form is None:
            file_inputs = soup.find_all('input', {'type': 'file'})
            if file_inputs:
                # 파일 입력이 있지만 form으로 감싸여 있지 않음 -> 폼 없이 JS로 업로드하는 케이스
                form = file_inputs[0].find_parent('form')
                if form is None:
                    # 후보로 처리: 체크할 수 있는 엔드포인트 추출 필요
                    print("[*] Found file input outside of a form — will scan page for upload endpoints (JS/data attributes)")

        # 2) 스크립트(내/외부)에서 upload 관련 문자열 찾기
        scripts = soup.find_all('script')
        for s in scripts:
            src = s.get('src')
            try:
                if src:
                    full = urljoin(self.upload_page_url, src)
                    r = self.session.get(full, timeout=6)
                    if r.status_code == 200:
                        for m in re.findall(r"(?:(?:https?:)?//[^\s'\"]+|/[^\s'\"]+|[\w\-_/]+\.php)", r.text):
                            if 'upload' in m.lower() or m.lower().endswith('.php') or 'uploads' in m.lower():
                                candidate_urls.add(urljoin(full, m))
                else:
                    # inline script
                    text = s.string or ''
                    for m in re.findall(r"(?:(?:https?:)?//[^\s'\"]+|/[^\s'\"]+|[\w\-_/]+\.php)", text):
                        if 'upload' in m.lower() or m.lower().endswith('.php') or 'uploads' in m.lower():
                            candidate_urls.add(urljoin(self.upload_page_url, m))
            except Exception:
                continue

        # 3) data-* 속성이나 onclick 등에 upload 키워드가 있는지 추출
        for tag in soup.find_all(True):
            for attr, val in tag.attrs.items():
                try:
                    s_val = ' '.join(val) if isinstance(val, (list, tuple)) else str(val)
                    if 'upload' in s_val.lower() or 'file' in s_val.lower():
                        for m in re.findall(r"(?:/[^\s'\"]+|[\w\-_/]+\.php|https?://[^\s'\"]+)", s_val):
                            candidate_urls.add(urljoin(self.upload_page_url, m))
                except Exception:
                    continue

        # 4) 초기 form 탐색 실패시: BFS로 같은 도메인 내 링크 탐색 + 후보 URL 프로빙
        if form is None:
            print("[*] Upload form not found on the provided page — searching links on the same host...")
            max_pages = 60
            visited = set()
            # visited: 이미 확인한 페이지 URL 집합 (중복 방문 방지)
            q = deque()
            # q: BFS(너비 우선 탐색) 큐. (url, soup) 튜플을 넣고 하나씩 꺼내며 검사
            q.append((self.upload_page_url, soup))
            pages_checked = 0
            while q and pages_checked < max_pages:
                current_url, current_soup = q.popleft()
                pages_checked += 1
                visited.add(current_url)
                # check current
                form = find_upload_form(current_soup)
                if form is not None:
                    found_at = current_url
                    break
                # enqueue same-host links and collect candidate endpoints from hrefs
                for a in current_soup.find_all('a', href=True):
                    href = a['href']
                    try:
                        full = urljoin(current_url, href)
                    except Exception:
                        continue
                    p = urlparse(full)
                    if p.netloc != parsed_root.netloc:
                        continue
                    if full in visited:
                        continue
                    try:
                        r = self.session.get(full, timeout=8)
                        if r.status_code == 200:
                            qsoup = BeautifulSoup(r.text, 'html.parser')
                            q.append((full, qsoup))
                            # href 자체가 upload 관련일 수 있음
                            if 'upload' in href.lower() or href.lower().endswith('.php') or 'uploads' in href.lower():
                                candidate_urls.add(full)
                    except Exception:
                        continue

            # if still not found, try some common upload paths and candidate URLs from scripts/attrs
            if form is None:
                common_paths = ['/vulnerabilities/upload/', '/upload.php', '/file_upload.php', '/uploads/', '/admin/upload.php']
                base_root = f"{parsed_root.scheme}://{parsed_root.netloc}"
                for cp in common_paths:
                    trial = urljoin(base_root, cp)
                    try:
                        r = self.session.get(trial, timeout=8)
                        if r.status_code == 200:
                            qsoup = BeautifulSoup(r.text, 'html.parser')
                            form = find_upload_form(qsoup)
                            if form is not None:
                                found_at = trial
                                soup = qsoup
                                break
                    except Exception:
                        continue

                # probe candidate_urls collected from JS/attributes
                if form is None:
                    for cand in list(candidate_urls):
                        try:
                            r = self.session.get(cand, timeout=6)
                            if r.status_code == 200:
                                qsoup = BeautifulSoup(r.text, 'html.parser')
                                form = find_upload_form(qsoup)
                                if form is not None:
                                    found_at = cand
                                    soup = qsoup
                                    break
                        except Exception:
                            continue

        # 최종적으로 form이 없으면 취약점 없음
        if form is None:
            return {'vulnerable': False, 'message': 'No upload form (file input) found on page or linked pages.'}

        # form 속성 추출
        action = form.get('action') or found_at
        action_url = urljoin(found_at, action)
        method = (form.get('method') or 'post').lower()
        enctype = (form.get('enctype') or '').lower()

        if method != 'post':
            return {'vulnerable': False, 'message': f'Upload form method is not POST (method={method}). Cannot upload.'}

        data = collect_form_data(form)
        print(f"[*] Found upload form -> action: {action_url}, enctype: {enctype}, extra fields: {list(data.keys())}")

        # 파일 입력 이름
        file_input = form.find('input', {'type': 'file'})
        file_field_name = file_input.get('name') or 'file'

        # 테스트 파일 생성
        # 실제로 업로드 가능한지 확인하기 위해 임시 디렉터리에 작은 PHP 파일을 만듭니다.
        # 파일 내용에 "File Upload Test" 문자열을 넣어 업로드 후 접근 시 확인합니다.
        test_content = '<?php echo "File Upload Test"; ?>'
        tmp_dir = tempfile.gettempdir()
        filename = f"test_upload_{uuid.uuid4().hex}.php"
        test_path = os.path.join(tmp_dir, filename)
        with open(test_path, 'w', encoding='utf-8') as f:
            f.write(test_content)
        print(f"[*] Created test file at: {test_path}")

        files = {}
        fobj = open(test_path, 'rb')
        # requests의 files 인자는 {필드이름: (파일명, 파일객체, MIME)} 형식의 튜플을 사용합니다.
        files[file_field_name] = (filename, fobj, 'application/x-php')

        try:
            # 전송
            try:
                response = self.session.post(action_url, data=data, files=files, timeout=15)
            except Exception as e:
                return {'vulnerable': False, 'message': f'Upload request failed: {e}'}
            finally:
                # 업로드 요청의 성공/실패와 상관없이 파일 객체는 반드시 닫아 리소스를 해제합니다.
                try:
                    fobj.close()
                except Exception:
                    pass

            # 업로드 성공 여부 추정
            # 1) 응답에서 업로드된 파일 링크 추출
            # guess_uploaded_urls: 응답의 헤더/본문/링크에서 업로드 위치로 보이는 URL들을 모아줍니다.
            candidates = guess_uploaded_urls(response, action_url)
            for url in candidates:
                try:
                    r = self.session.get(url, timeout=10)
                    if r.status_code == 200 and 'File Upload Test' in r.text:
                        return {'vulnerable': True, 'message': 'File upload vulnerability detected', 'uploaded_file_url': url}
                except Exception:
                    continue

            # 2) 응답 본문에서 'success' 관련 키워드 탐색
            if re.search(r'successfully uploaded|file uploaded|upload complete|uploaded successfully', response.text, flags=re.I):
                return {'vulnerable': True, 'message': 'Server reports successful upload but location not found in response', 'uploaded_file_url': None}

            return {'vulnerable': False, 'message': 'No evidence of successful upload found.'}

        finally:
            # 임시파일 정리: 스캔이 끝나면 테스트 파일은 반드시 삭제합니다.
            try:
                if os.path.exists(test_path):
                    os.remove(test_path)
                    print(f"[*] Removed temp file: {test_path}")
            except Exception as e:
                print(f"[!] Warning: could not remove temp file: {e}")


def run_interactive():
    full_url = input("테스트할 취약점 페이지 전체 URL을 입력하세요 : ").strip()
    if not full_url:
        print("URL이 입력되지 않았습니다. 종료합니다.")
        return
    scanner = FileUploadVulnerability(full_url)
    result = scanner.test_file_upload()
    if result.get('vulnerable'):
        print(f"[!] 취약점 발견: {result.get('message')}")
        if result.get('uploaded_file_url'):
            print(f"[!] 업로드된 파일 접근 URL: {result.get('uploaded_file_url')}")
    else:
        print(f"[*] 취약점 없음: {result.get('message')}")


if __name__ == '__main__':
    run_interactive()

