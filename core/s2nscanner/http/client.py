"""
공통 HttpClient 모듈
- 각 플러그인에서 동일하게 세션을 재사용하기 위해 사용
- 내부적으로 requests.Session을 래핑해서 재시도, 타임아웃, 헤더 등을 일원화함.
- 각 파일들이 import requests...를 각각 요청하면 여러 문제가 발생하기 쉬워서 공통 인터페이스를 만드는 게 좋음
"""

# 임시 코드
import requests
import time

class HttpClient:
    def __init__(self, retry: int = 1, backoff: float = 0.2):
        # 모든 요청에 사용할 세션 객체
        self.s = requests.Session()
        self.retry = retry
        self.backoff = backoff
    
    def get(self, url, **kwargs):
        # GET 요청 전송 (기본적으로 재시도 기능 포함)
        for i in range(self.retry + 1):
            try:
                return self.s.get(url, **kwargs)
            except requests.RequestException as e:
                if i == self.retry:
                    raise
                time.sleep(self.backoff * (2 ** i))

    def post(self, url, data=None, **kwargs):
        # POST 요청 전송 (기본적으로 재시도 기능 포함)
        for i in range(self.retry + 1):
            try:
                return self.s.post(url, data=data, **kwargs)
            except requests.RequestException as e:
                if i == self.retry:
                    raise
                time.sleep(self.backoff * (2 ** i))