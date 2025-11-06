# 헬퍼 함수들 (_find_upload_form, _collect_form_data 등)

import re  # 정규식을 사용해 텍스트에서 패턴을 찾기 위한 표준 라이브러리
from bs4 import BeautifulSoup  # HTML 파싱을 위한 라이브러리 (응답 본문 분석)
from urllib.parse import urljoin  # 상대 경로를 절대 URL로 바꿀 때 사용

def find_upload_form(soup):
    """<input type="file">을 포함한 첫 번째 <form> 요소를 찾아 반환합니다. 없으면 None."""
    # 페이지의 모든 폼 태그 수집
    forms = soup.find_all('form')  
    # 각 폼을 확인하면서
    for form in forms:  
        # 파일 업로드 입력이 있으면
        if form.find('input', {'type': 'file'}) is not None:  
            # 해당 폼을 반환
            return form  
    # 끝까지 못 찾으면 None
    return None  

def collect_form_data(form):
    """폼에서 파일 입력을 제외한 값들을 사전(dict)으로 모읍니다."""
    # 전송할 키-값 쌍을 담을 컨테이너
    data = {}  
    # 폼 내 모든 input 순회
    for inp in form.find_all('input'):  
        # input 타입 (없으면 빈 문자열)
        itype = (inp.get('type') or '').lower()  
        # 서버가 받는 파라미터 이름
        name = inp.get('name')  
        # name 속성이 없으면 전송 불가하므로 건너뜀
        if not name:  
            continue
        # 파일은 files 인자로 따로 전송하므로 제외
        if itype == 'file':  
            continue
        # 버튼류는 데이터 전송에 필요 없음
        if itype in ('submit', 'button'):  
            continue
        # 기본값이 있으면 함께 보냄
        data[name] = inp.get('value', '')  
    # 수집된 데이터 반환
    return data  

def find_login_form(soup):
    """비밀번호 입력이 포함된 로그인 폼을 찾아 반환합니다. 없으면 None."""
    # 모든 폼 대상으로
    forms = soup.find_all('form')  
    # 각 폼을 확인하면서
    for form in forms:
        # password 필드 존재 여부 확인
        if form.find('input', {'type': 'password'}) is not None:  
            # 로그인 폼으로 판단
            return form  
    # 없으면 None
    return None  

def perform_login(session, form, base_url, username, password):
    """세션을 사용해 로그인 폼에 아이디/비밀번호를 제출합니다. 응답 또는 None을 반환."""
    # 폼의 action이 없으면 현재 URL로 보냄
    action = form.get('action') or base_url  
    # 상대 경로일 수 있으니 절대 URL로 변환
    action_url = urljoin(base_url, action)  
    # 전송할 폼 데이터 컨테이너
    data = {}  
    # 사용자명 필드 이름을 나중에 탐색해 설정
    username_field = None  
    # 비밀번호 필드 이름을 나중에 탐색해 설정
    password_field = None  
    # 폼 내 모든 input 순회
    for inp in form.find_all('input'):
        # name 속성이 없으면 전송 불가
        name = inp.get('name')
        if not name:  
            continue
        # input 타입
        itype = (inp.get('type') or '').lower()
        # 첫 password 입력을 비번 필드로 사용
        if itype == 'password' and password_field is None:  
            password_field = name
            continue
        # 사용자명 후보 찾기
        if itype in ('text', 'email') and username_field is None:  
            nm = name.lower()
            if any(k in nm for k in ('user', 'email', 'login', 'id')):
                username_field = name
            elif username_field is None:
                username_field = name  # 힌트가 없으면 첫 텍스트 입력 사용
        # 토큰/히든 값 등은 그대로 전송
        if itype in ('hidden', 'submit'):  
            data[name] = inp.get('value', '')
    # 위에서 못찾았으면 다시 한 번 텍스트/이메일 입력을 훑음
    if username_field is None:  
        for inp in form.find_all('input'):
            itype = (inp.get('type') or '').lower()
            name = inp.get('name')
            if itype in ('text', 'email') and name:
                username_field = name
                break
    # 사용자명 값 채워넣기
    if username_field:
        data[username_field] = username  
    # 비밀번호 값 채워넣기
    if password_field:
        data[password_field] = password  
    try:
        # 로그인 요청 전송
        resp = session.post(action_url, data=data, timeout=10)  
        return resp
    except Exception:
        # 요청 실패 시 None
        return None  

def guess_uploaded_urls(response, action_url):
    """응답의 HTML/헤더에서 업로드된 파일 위치일 가능성이 있는 URL 후보를 추출합니다."""
    # 본문 HTML 파싱
    soup = BeautifulSoup(response.text, 'html.parser')  
    # 후보 URL들을 담는 리스트
    candidates = []  
    # 리다이렉트 헤더가 있으면 해당 위치도 후보
    loc = response.headers.get('Location')  
    if loc:
        candidates.append(urljoin(action_url, loc))
    # a 태그의 링크를 조사
    for a in soup.find_all('a', href=True):  
        href = a['href']
        if 'upload' in href.lower() or href.lower().endswith('.php') or 'uploads' in href.lower():
            candidates.append(urljoin(action_url, href))
    # href/src 패턴 검색
    for m in re.findall(r"(?:href|src)=[\'\"]([^\'\"]+)[\'\"]", response.text, flags=re.I):  
        if 'upload' in m.lower() or m.lower().endswith('.php') or 'uploads' in m.lower():
            candidates.append(urljoin(action_url, m))
    # 중복 제거를 위한 순서 보존 리스트
    seen = []  
    # 중복 제거
    for c in candidates:
        if c not in seen:
            seen.append(c)
    # 중복 제거된 후보 목록 반환
    return seen  
