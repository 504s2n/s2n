from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# ============================================================================
# Enum Types
# ============================================================================

class Severity(str, Enum):
    """심각도 레벨"""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AuthType(str, Enum):
    """인증 타입"""
    NONE = "NONE"
    BASIC = "BASIC"
    BEARER = "BEARER"
    API_KEY = "API_KEY"
    COOKIE = "COOKIE"
    CUSTOM = "CUSTOM"


class OutputFormat(str, Enum):
    """출력 형식"""
    JSON = "JSON"
    HTML = "HTML"
    CSV = "CSV"
    CONSOLE = "CONSOLE"
    MULTI = "MULTI"


class ConsoleMode(str, Enum):
    """콘솔 출력 모드"""
    SILENT = "SILENT"
    SUMMARY = "SUMMARY"
    VERBOSE = "VERBOSE"
    DEBUG = "DEBUG"


class LogLevel(str, Enum):
    """로그 레벨"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    """확신도"""
    CERTAIN = "CERTAIN"
    FIRM = "FIRM"
    TENTATIVE = "TENTATIVE"


class PluginStatus(str, Enum):
    """플러그인 실행 상태"""
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    TIMEOUT = "TIMEOUT"


# ============================================================================
# Input Types (입력 타입)
# ============================================================================

@dataclass(frozen=True)
class ScanRequest:
    """스캔 요청의 최상위 데이터 구조"""
    target_url: str
    plugins: List[str] = field(default_factory=list)
    config_path: Optional[Path] = None
    auth_type: Optional[AuthType] = None
    output_format: OutputFormat = OutputFormat.JSON
    output_path: Optional[Path] = None
    verbose: bool = False


@dataclass(frozen=True)
class CLIArguments:
    """CLI 명령어 인자를 구조화"""
    url: str
    plugin: List[str] = field(default_factory=list)
    config: Optional[str] = None
    auth: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    output: Optional[str] = None
    depth: int = 2
    verbose: bool = False
    log_file: Optional[str] = None


# ============================================================================
# Configuration Types (설정 타입)
# ============================================================================

@dataclass(frozen=True)
class ScannerConfig:
    """스캐너 엔진 동작 설정"""
    crawl_depth: int = 2
    max_threads: int = 5
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    user_agent: str = "S2N-Scanner/0.1.0"
    follow_redirects: bool = True
    verify_ssl: bool = True


@dataclass(frozen=True)
class PluginConfig:
    """개별 플러그인 설정"""
    enabled: bool = True
    timeout: int = 30
    max_payloads: Optional[int] = None
    payload_file: Optional[Path] = None
    severity_threshold: Severity = Severity.LOW
    skip_patterns: List[str] = field(default_factory=list)
    custom_params: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthConfig:
    """인증 설정"""
    auth_type: AuthType
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    api_key: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class NetworkConfig:
    """네트워크 레이어 설정"""
    max_connections: int = 100
    connection_timeout: int = 10
    read_timeout: int = 30
    rate_limit: Optional[float] = None
    proxy: Optional[str] = None
    dns_cache_ttl: int = 300


@dataclass(frozen=True)
class OutputConfig:
    """출력 설정"""
    format: OutputFormat = OutputFormat.JSON
    path: Optional[Path] = None
    pretty_print: bool = True
    include_timestamps: bool = True
    include_metadata: bool = True
    console_mode: ConsoleMode = ConsoleMode.SUMMARY


@dataclass(frozen=True)
class LoggingConfig:
    """로깅 설정"""
    level: LogLevel = LogLevel.INFO
    file_path: Optional[Path] = None
    console_output: bool = True
    format: str = "%(asctime)s - %(levelname)s - %(message)s"
    max_file_size: int = 10485760
    backup_count: int = 3


@dataclass(frozen=True)
class ScanConfig:
    """전체 스캔 설정을 관리"""
    target_url: str
    scanner_config: ScannerConfig = field(default_factory=ScannerConfig)
    plugin_configs: Dict[str, PluginConfig] = field(default_factory=dict)
    auth_config: Optional[AuthConfig] = None
    network_config: NetworkConfig = field(default_factory=NetworkConfig)
    output_config: OutputConfig = field(default_factory=OutputConfig)
    logging_config: LoggingConfig = field(default_factory=LoggingConfig)


# ============================================================================
# Execution Types (실행 타입)
# ============================================================================

@dataclass
class ScanContext:
    """스캔 실행 중 공유되는 컨텍스트"""
    scan_id: str
    start_time: datetime
    config: ScanConfig
    http_client: Any  # HTTPClient 인스턴스
    crawler: Any  # Crawler 인스턴스
    session_data: Dict[str, Any] = field(default_factory=dict)
    discovered_urls: Set[str] = field(default_factory=set)
    visited_urls: Set[str] = field(default_factory=set)


@dataclass
class PluginContext:
    """플러그인 실행 시 제공되는 컨텍스트"""
    plugin_name: str
    scan_context: ScanContext
    plugin_config: PluginConfig
    target_urls: List[str] = field(default_factory=list)
    logger: Any = None  # Logger 인스턴스


# ============================================================================
# Result Types (결과 타입)
# ============================================================================

@dataclass(frozen=True)
class HTTPRequest:
    """HTTP 요청 정보"""
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class HTTPResponse:
    """HTTP 응답 정보"""
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0


@dataclass(frozen=True)
class Finding:
    """개별 취약점 정보"""
    id: str
    plugin: str
    severity: Severity
    title: str
    description: str
    url: Optional[str] = None
    parameter: Optional[str] = None
    method: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    request: Optional[HTTPRequest] = None
    response: Optional[HTTPResponse] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    confidence: Confidence = Confidence.FIRM
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass(frozen=True)
class PluginError:
    """플러그인 에러 정보"""
    error_type: str
    message: str
    traceback: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PluginResult:
    """플러그인 실행 결과"""
    plugin_name: str
    status: PluginStatus
    findings: List[Finding] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    urls_scanned: int = 0
    requests_sent: int = 0
    error: Optional[PluginError] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanSummary:
    """스캔 결과 요약"""
    total_vulnerabilities: int = 0
    severity_counts: Dict[Severity, int] = field(default_factory=dict)
    plugin_counts: Dict[str, int] = field(default_factory=dict)
    total_urls_scanned: int = 0
    total_requests: int = 0
    success_rate: float = 0.0
    has_critical: bool = False
    has_high: bool = False


@dataclass(frozen=True)
class ScanMetadata:
    """스캔 메타데이터"""
    hostname: str
    username: str
    python_version: str
    os_info: str
    cli_args: Optional[List[str]] = None
    config_file: Optional[str] = None


@dataclass(frozen=True)
class ScanReport:
    """전체 스캔 리포트"""
    scan_id: str
    target_url: str
    scanner_version: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    config: ScanConfig
    plugin_results: List[PluginResult] = field(default_factory=list)
    summary: Optional[ScanSummary] = None
    metadata: Optional[ScanMetadata] = None


# ============================================================================
# Error Types (에러 타입)
# ============================================================================

class S2NException(Exception):
    """모든 S2N 예외의 베이스 클래스"""
    def __init__(
        self,
        message: str,
        error_code: str = "UNKNOWN",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.timestamp = datetime.now()
        self.context = context or {}


class NetworkError(S2NException):
    """네트워크 관련 에러"""
    pass


class AuthenticationError(S2NException):
    """인증 실패"""
    pass


class ConfigurationError(S2NException):
    """설정 오류"""
    pass


class PluginException(S2NException):
    """플러그인 오류"""
    pass


class CrawlerError(S2NException):
    """크롤러 오류"""
    pass


class ValidationError(S2NException):
    """입력 검증 오류"""
    pass


@dataclass(frozen=True)
class ErrorReport:
    """에러 정보 리포트"""
    error_type: str
    message: str
    traceback: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    context: Dict[str, Any] = field(default_factory=dict)
    recoverable: bool = False
    retry_count: int = 0


# ============================================================================
# Output Types (출력 타입)
# ============================================================================

@dataclass(frozen=True)
class ProgressInfo:
    """진행 상황 정보"""
    current: int
    total: int
    percentage: float
    message: str


@dataclass(frozen=True)
class ConsoleOutput:
    """콘솔 출력 데이터"""
    mode: ConsoleMode
    summary_lines: List[str] = field(default_factory=list)
    detail_lines: List[str] = field(default_factory=list)
    progress_info: Optional[ProgressInfo] = None


@dataclass(frozen=True)
class JSONOutput:
    """JSON 출력 형식"""
    scan_report: ScanReport
