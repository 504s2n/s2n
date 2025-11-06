import requests
from bs4 import BeautifulSoup
import os
import tempfile
import uuid
import re
from urllib.parse import urljoin, urlparse
from collections import deque


class FileUploadVulnerability:
    """
    범용 파일 업로드 취약점 검사기
    - 업로드 폼 존재 여부 확인
    - CSRF/hidden inputs 처리 시도
    - 테스트 파일 업로드 시도 및 업로드 위치 추측
    """

    def __init__(self, upload_page_url, session=None):
        self.upload_page_url = upload_page_url
        self.session = session or requests.Session()

    def _find_upload_form(self, soup):
        # 파일 입력이 포함된 첫 번째 form을 찾음
        forms = soup.find_all('form')
        for form in forms:
            if form.find('input', {'type': 'file'}) is not None:
                return form
        return None

    def _collect_form_data(self, form):
        data = {}
        for inp in form.find_all('input'):
            itype = (inp.get('type') or '').lower()
            name = inp.get('name')
            if not name:
                continue
            # 파일 입력은 제외
            if itype == 'file':
                continue
            # 제출 버튼은 제외
            if itype in ('submit', 'button'):
                continue
            data[name] = inp.get('value', '')
        return data

    def _find_login_form(self, soup):
        # password 입력을 포함한 form을 로그인 폼으로 간주
        forms = soup.find_all('form')
        for form in forms:
            if form.find('input', {'type': 'password'}) is not None:
                return form
        return None

    def _perform_login(self, form, base_url, username, password):
        # form의 hidden/기타 필드를 수집하고 username/password 필드에 값을 넣어 제출
        action = form.get('action') or base_url
        action_url = urljoin(base_url, action)
        data = {}
        username_field = None
        password_field = None
        for inp in form.find_all('input'):
            name = inp.get('name')
            if not name:
                continue
            itype = (inp.get('type') or '').lower()
            # 찾을 필드 이름 추정
            if itype == 'password' and password_field is None:
                password_field = name
                continue
            if itype in ('text', 'email') and username_field is None:
                # prefer names containing user/login/email
                nm = name.lower()
                if any(k in nm for k in ('user', 'email', 'login', 'id')):
                    username_field = name
                elif username_field is None:
                    username_field = name
                # continue collecting hidden/default values below
            # hidden or other inputs
            if itype in ('hidden', 'submit'):
                data[name] = inp.get('value', '')
        # if not found username field, try to pick first text input
        if username_field is None:
            for inp in form.find_all('input'):
                itype = (inp.get('type') or '').lower()
                name = inp.get('name')
                if itype in ('text', 'email') and name:
                    username_field = name
                    break
        # finally, set credentials into data
        if username_field:
            data[username_field] = username
        if password_field:
            data[password_field] = password

        try:
            resp = self.session.post(action_url, data=data, timeout=10)
            return resp
        except Exception as e:
            print(f"[!] Login request failed: {e}")
            return None

    def _guess_uploaded_urls(self, response, action_url):
        # 응답 HTML에서 uploads 경로나 .php 링크를 찾음
        soup = BeautifulSoup(response.text, 'html.parser')
        candidates = []
        # 1) Location header
        loc = response.headers.get('Location')
        if loc:
            candidates.append(urljoin(action_url, loc))
        # 2) a 태그의 href
        for a in soup.find_all('a', href=True):
            href = a['href']
            if 'upload' in href.lower() or href.lower().endswith('.php') or 'uploads' in href.lower():
                candidates.append(urljoin(action_url, href))
        # 3) 텍스트에서 상대/절대 경로 추출
        for m in re.findall(r"(?:href|src)=[\'\"]([^\'\"]+)[\'\"]", response.text, flags=re.I):
            if 'upload' in m.lower() or m.lower().endswith('.php') or 'uploads' in m.lower():
                candidates.append(urljoin(action_url, m))
        # 고유화
        seen = []
        for c in candidates:
            if c not in seen:
                seen.append(c)
        return seen

    def test_file_upload(self):
        # 페이지 로드
        print(f"[*] Fetching upload page: {self.upload_page_url}")
        try:
            resp = self.session.get(self.upload_page_url, timeout=10)
        except Exception as e:
            return {'vulnerable': False, 'message': f'Failed to fetch page: {e}'}

        soup = BeautifulSoup(resp.text, 'html.parser')
        form = self._find_upload_form(soup)
        found_at = self.upload_page_url

        # 로그인 폼이 감지되면 별도의 로그인 플러그인에서 처리해야 하므로
        # 이 페이지 자체에 업로드 폼이 있는지 여부만 판단합니다.
        if form is None:
            login_form = self._find_login_form(soup)
            if login_form is not None:
                # 로그인 페이지로 판단됨 — 로그인 없이 이 페이지에서 업로드 폼이 없으므로 취약점 없음으로 간주
                return {'vulnerable': False, 'message': 'Page requires login; no upload form found on this login page.'}

        # 추가 탐색: 파일 input이 폼 바깥에 존재하는 경우, data-* 혹은 onclick 등에 upload 관련 엔드포인트가 있을 수 있음
        candidate_urls = set()
        parsed_root = urlparse(self.upload_page_url)

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
            q = deque()
            q.append((self.upload_page_url, soup))
            pages_checked = 0
            while q and pages_checked < max_pages:
                current_url, current_soup = q.popleft()
                pages_checked += 1
                visited.add(current_url)
                # check current
                form = self._find_upload_form(current_soup)
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
                            form = self._find_upload_form(qsoup)
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
                                form = self._find_upload_form(qsoup)
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

        data = self._collect_form_data(form)
        print(f"[*] Found upload form -> action: {action_url}, enctype: {enctype}, extra fields: {list(data.keys())}")

        # 파일 입력 이름
        file_input = form.find('input', {'type': 'file'})
        file_field_name = file_input.get('name') or 'file'

        # 테스트 파일 생성
        test_content = '<?php echo "File Upload Test"; ?>'
        tmp_dir = tempfile.gettempdir()
        filename = f"test_upload_{uuid.uuid4().hex}.php"
        test_path = os.path.join(tmp_dir, filename)
        with open(test_path, 'w', encoding='utf-8') as f:
            f.write(test_content)
        print(f"[*] Created test file at: {test_path}")

        files = {}
        fobj = open(test_path, 'rb')
        files[file_field_name] = (filename, fobj, 'application/x-php')

        try:
            # 전송
            try:
                response = self.session.post(action_url, data=data, files=files, timeout=15)
            except Exception as e:
                return {'vulnerable': False, 'message': f'Upload request failed: {e}'}
            finally:
                try:
                    fobj.close()
                except Exception:
                    pass

            # 업로드 성공 여부 추정
            # 1) 응답에서 업로드된 파일 링크 추출
            candidates = self._guess_uploaded_urls(response, action_url)
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
            # 임시파일 정리
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
