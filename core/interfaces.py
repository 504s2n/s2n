from dataclasses import dataclass
from enum import Enum
from typing import Optional

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class Finding:
    id: str                 # 고유 식별자 (예: UUID, 해시 등)
    plugin: str             # 탐지한 플러그인 이름 (예: "xss", "sqlinjection")
    severity: Severity      # 심각도
    title: str              # 짧은 제목
    description: str        # 상세 설명
    url: Optional[str] = None        # 발견 위치(타겟 URL 등)
    payload: Optional[str] = None    # 사용한 페이로드(해당 시)
    evidence: Optional[str] = None   # 증거(응답 일부, 로그 등)

