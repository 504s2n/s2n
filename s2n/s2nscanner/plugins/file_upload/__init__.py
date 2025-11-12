# 이 파일은 이 폴더를 파이썬 '패키지'로 인식시키는 초기화 파일입니다.
# 패키지를 import할 때 외부에 보여줄(공개할) 객체들을 정리하는 용도로 사용합니다.
  
from .file_upload_main import main as Plugin

__all__ = ["Plugin"]