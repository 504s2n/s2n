# S2N Scanner - 데이터 타입 정의 문서 (KO)

## 목차

1. [개요](#개요)
2. [타입 계층 구조](#타입-계층-구조)
3. [입력 타입 (Input Types)](#입력-타입-input-types)
4. [설정 타입 (Configuration Types)](#설정-타입-configuration-types)
5. [실행 타입 (Execution Types)](#실행-타입-execution-types)
6. [결과 타입 (Result Types)](#결과-타입-result-types)
7. [에러 타입 (Error Types)](#에러-타입-error-types)
8. [출력 타입 (Output Types)](#출력-타입-output-types)

---

## 개요

### 목적

S2N Scanner의 모든 데이터 흐름에서 사용되는 공통 타입을 정의합니다.
- **CLI 방식**과 **Python Import 방식** 모두 동일한 타입 사용
- 각 단계(입력 → 설정 → 실행 → 결과 → 출력)별 타입 명확화
- 타입 안전성 및 데이터 일관성 보장

### 설계 원칙

1. **불변성**: 가능한 한 불변 객체 사용
2. **직렬화 가능**: JSON/YAML 변환 지원
3. **타입 힌트**: 모든 필드에 명시적 타입 정의
4. **문서화**: 각 필드의 목적과 제약사항 명시
5. **확장성**: 새로운 플러그인/기능 추가 용이

---

## 타입 계층 구조

```bash
Entry Point (CLI/Package)
    ↓
Input Types (ScanRequest, CLIArguments)
    ↓
Configuration Types (ScanConfig, PluginConfig, AuthConfig)
    ↓
Execution Types (ScanContext, PluginContext)
    ↓
Result Types (Finding, PluginResult, ScanReport)
    ↓
Output Types (JSONOutput, HTMLOutput, ConsoleOutput)
```

## 데이터 흐름 요약

1. **입력 단계**: `CLIArguments` → `ScanRequest`
2. **설정 단계**: `ScanRequest` + `Config Files` → `ScanConfig`
3. **실행 단계**: `ScanConfig` → `ScanContext` → `PluginContext`
4. **결과 단계**: `PluginContext` → `Finding` → `PluginResult` → `ScanReport`
5. **출력 단계**: `ScanReport` → `JSONOutput` / `HTMLOutput` / `ConsoleOutput`

---

## 입력 타입 (Input Types)

### 1. `ScanRequest`

**용도**: 스캔 요청의 최상위 데이터 구조

**필드**:
| 필드명 | 타입 | 필수 | 기본값 | 설명 |
|--------|------|------|--------|------|
| `target_url` | `str` | ✅ | - | 스캔 대상 URL |
| `plugins` | `List[str]` | ❌ | `[]` | 사용할 플러그인 목록 |
| `config_path` | `Optional[Path]` | ❌ | `None` | 설정 파일 경로 |
| `auth_type` | `Optional[AuthType]` | ❌ | `None` | 인증 타입 |
| `output_format` | `OutputFormat` | ❌ | `JSON` | 출력 형식 |
| `output_path` | `Optional[Path]` | ❌ | `None` | 출력 파일 경로 |
| `verbose` | `bool` | ❌ | `False` | 상세 로그 출력 여부 |

**사용 시점**: CLI 인자 파싱 후 또는 Python API 호출 시

---

### 2. `CLIArguments`

**용도**: CLI 명령어 인자를 구조화

**필드**:
| 필드명 | 타입 | 필수 | 설명 |
|--------|------|------|------|
| `url` | `str` | ✅ | `--url, -u` |
| `plugin` | `List[str]` | ❌ | `--plugin, -p` (다중 선택) |
| `config` | `Optional[str]` | ❌ | `--config, -c` |
| `auth` | `Optional[str]` | ❌ | `--auth, -a` |
| `username` | `Optional[str]` | ❌ | `--username` |
| `password` | `Optional[str]` | ❌ | `--password` |
| `output` | `Optional[str]` | ❌ | `--output, -o` |
| `depth` | `int` | ❌ | `--depth, -d` (기본값: 2) |
| `verbose` | `bool` | ❌ | `--verbose, -v` |
| `log_file` | `Optional[str]` | ❌ | `--log-file` |

**사용 시점**: CLI 명령어 파싱 직후

---

## 설정 타입 (Configuration Types)

### 3. `ScanConfig`

**용도**: 전체 스캔 설정을 관리

**필드**:
| 필드명 | 타입 | 기본값 | 설명 |
|--------|------|--------|------|
| `target_url` | `str` | - | 스캔 대상 URL |
| `scanner_config` | `ScannerConfig` | - | 스캐너 설정 |
| `plugin_configs` | `Dict[str, PluginConfig]` | `{}` | 플러그인별 설정 |
| `auth_config` | `Optional[AuthConfig]` | `None` | 인증 설정 |
| `network_config` | `NetworkConfig` | - | 네트워크 설정 |
| `output_config` | `OutputConfig` | - | 출력 설정 |
| `logging_config` | `LoggingConfig` | - | 로깅 설정 |

**생성 방법**:

- CLI 인자 + 기본값
- YAML 파일 로드
- Python API에서 직접 생성

---

### 4. `ScannerConfig`

**용도**: 스캐너 엔진 동작 설정

**필드**:
| 필드명 | 타입 | 기본값 | 범위 | 설명 |
|--------|------|--------|------|------|
| `crawl_depth` | `int` | `2` | 1-10 | 크롤링 깊이 |
| `max_threads` | `int` | `5` | 1-20 | 최대 스레드 수 |
| `timeout` | `int` | `30` | 1-300 | 요청 타임아웃 (초) |
| `max_retries` | `int` | `3` | 0-10 | 최대 재시도 횟수 |
| `retry_delay` | `float` | `1.0` | 0.1-10.0 | 재시도 간격 (초) |
| `user_agent` | `str` | `"S2N-Scanner/0.1.0"` | - | User-Agent 헤더 |
| `follow_redirects` | `bool` | `True` | - | 리다이렉트 따라가기 |
| `verify_ssl` | `bool` | `True` | - | SSL 인증서 검증 |

---

### 5. `PluginConfig`

**용도**: 개별 플러그인 설정

**필드**:
| 필드명 | 타입 | 기본값 | 설명 |
|--------|------|--------|------|
| `enabled` | `bool` | `True` | 플러그인 활성화 여부 |
| `timeout` | `int` | `30` | 플러그인 타임아웃 |
| `max_payloads` | `Optional[int]` | `None` | 최대 페이로드 수 |
| `payload_file` | `Optional[Path]` | `None` | 커스텀 페이로드 파일 |
| `severity_threshold` | `Severity` | `LOW` | 최소 보고 심각도 |
| `skip_patterns` | `List[str]` | `[]` | 제외할 URL 패턴 |
| `custom_params` | `Dict[str, Any]` | `{}` | 플러그인별 커스텀 파라미터 |

**예시 (SQL Injection 플러그인)**:
```python
PluginConfig(
    enabled=True,
    timeout=10,
    max_payloads=50,
    custom_params={
        'error_patterns': ['mysql_fetch', 'ORA-'],
        'blind_sleep_time': 5
    }
)
```

---

### 6. `AuthConfig`

**용도**: 인증 설정

**필드**:
| 필드명 | 타입 | 필수 | 설명 |
|--------|------|------|------|
| `auth_type` | `AuthType` | ✅ | 인증 타입 |
| `username` | `Optional[str]` | ❌ | 사용자명 |
| `password` | `Optional[str]` | ❌ | 비밀번호 |
| `token` | `Optional[str]` | ❌ | Bearer 토큰 |
| `api_key` | `Optional[str]` | ❌ | API 키 |
| `headers` | `Dict[str, str]` | `{}` | 커스텀 헤더 |
| `cookies` | `Dict[str, str]` | `{}` | 쿠키 |

**AuthType Enum**:
- `NONE`: 인증 없음
- `BASIC`: HTTP Basic Auth
- `BEARER`: Bearer Token
- `API_KEY`: API Key
- `COOKIE`: Cookie-based
- `CUSTOM`: Custom Headers

---

### 7. `NetworkConfig`

**용도**: 네트워크 레이어 설정

**필드**:
| 필드명 | 타입 | 기본값 | 설명 |
|--------|------|--------|------|
| `max_connections` | `int` | `100` | 최대 동시 연결 수 |
| `connection_timeout` | `int` | `10` | 연결 타임아웃 (초) |
| `read_timeout` | `int` | `30` | 읽기 타임아웃 (초) |
| `rate_limit` | `Optional[float]` | `None` | 초당 최대 요청 수 |
| `proxy` | `Optional[str]` | `None` | 프록시 URL |
| `dns_cache_ttl` | `int` | `300` | DNS 캐시 TTL (초) |

---

### 8. `OutputConfig`

**용도**: 출력 설정

**필드**:
| 필드명 | 타입 | 기본값 | 설명 |
|--------|------|--------|------|
| `format` | `OutputFormat` | `JSON` | 출력 형식 |
| `path` | `Optional[Path]` | `None` | 출력 파일 경로 |
| `pretty_print` | `bool` | `True` | JSON pretty print |
| `include_timestamps` | `bool` | `True` | 타임스탬프 포함 |
| `include_metadata` | `bool` | `True` | 메타데이터 포함 |
| `console_mode` | `ConsoleMode` | `SUMMARY` | 콘솔 출력 모드 |

**OutputFormat Enum**:
- `JSON`: JSON 파일
- `HTML`: HTML 리포트
- `CSV`: CSV 파일
- `CONSOLE`: 콘솔 출력만
- `MULTI`: 다중 형식

**ConsoleMode Enum**:
- `SILENT`: 출력 없음
- `SUMMARY`: 요약만
- `VERBOSE`: 상세 출력
- `DEBUG`: 디버그 정보 포함

---

### 9. `LoggingConfig`

**용도**: 로깅 설정

**필드**:
| 필드명 | 타입 | 기본값 | 설명 |
|--------|------|--------|------|
| `level` | `LogLevel` | `INFO` | 로그 레벨 |
| `file_path` | `Optional[Path]` | `None` | 로그 파일 경로 |
| `console_output` | `bool` | `True` | 콘솔 출력 여부 |
| `format` | `str` | `"%(asctime)s - %(levelname)s - %(message)s"` | 로그 포맷 |
| `max_file_size` | `int` | `10485760` | 최대 파일 크기 (바이트) |
| `backup_count` | `int` | `3` | 백업 파일 개수 |

**LogLevel Enum**:
- `DEBUG`
- `INFO`
- `WARNING`
- `ERROR`
- `CRITICAL`

---

## 실행 타입 (`Execution Types`)

### 10. `ScanContext`

**용도**: 스캔 실행 중 공유되는 컨텍스트

**필드**:
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `scan_id` | `str` | 스캔 고유 ID (UUID) |
| `start_time` | `datetime` | 스캔 시작 시간 |
| `config` | `ScanConfig` | 스캔 설정 |
| `http_client` | `HTTPClient` | HTTP 클라이언트 인스턴스 |
| `crawler` | `Crawler` | 크롤러 인스턴스 |
| `session_data` | `Dict[str, Any]` | 세션 데이터 |
| `discovered_urls` | `Set[str]` | 발견된 URL 목록 |
| `visited_urls` | `Set[str]` | 방문한 URL 목록 |

---

### 11. `PluginContext`

**용도**: 플러그인 실행 시 제공되는 컨텍스트

**필드**:
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `plugin_name` | `str` | 플러그인 이름 |
| `scan_context` | `ScanContext` | 전체 스캔 컨텍스트 |
| `plugin_config` | `PluginConfig` | 플러그인 설정 |
| `target_urls` | `List[str]` | 스캔할 URL 목록 |
| `logger` | `Logger` | 로거 인스턴스 |

---

## 결과 타입 (`Result Types`)

### 12. `Finding`

**용도**: 개별 취약점 정보

**필드**:
| 필드명 | 타입 | 필수 | 설명 |
|--------|------|------|------|
| `id` | `str` | ✅ | 고유 ID (예: "sql-001") |
| `plugin` | `str` | ✅ | 플러그인 이름 |
| `severity` | `Severity` | ✅ | 심각도 |
| `title` | `str` | ✅ | 취약점 제목 |
| `description` | `str` | ✅ | 상세 설명 |
| `url` | `Optional[str]` | ❌ | 취약점 발견 URL |
| `parameter` | `Optional[str]` | ❌ | 취약한 파라미터명 |
| `method` | `Optional[str]` | ❌ | HTTP 메서드 |
| `payload` | `Optional[str]` | ❌ | 공격 페이로드 |
| `evidence` | `Optional[str]` | ❌ | 취약점 증거 |
| `request` | `Optional[HTTPRequest]` | ❌ | 요청 정보 |
| `response` | `Optional[HTTPResponse]` | ❌ | 응답 정보 |
| `remediation` | `Optional[str]` | ❌ | 수정 방법 |
| `references` | `List[str]` | `[]` | 참고 링크 |
| `cwe_id` | `Optional[str]` | ❌ | CWE ID |
| `cvss_score` | `Optional[float]` | ❌ | CVSS 점수 (0.0-10.0) |
| `cvss_vector` | `Optional[str]` | ❌ | CVSS 벡터 |
| `confidence` | `Confidence` | `MEDIUM` | 확신도 |
| `timestamp` | `datetime` | - | 발견 시간 (자동) |

**Severity Enum**:
- `CRITICAL`: 치명적
- `HIGH`: 높음
- `MEDIUM`: 중간
- `LOW`: 낮음
- `INFO`: 정보성

**Confidence Enum**:
- `CERTAIN`: 확실
- `FIRM`: 확고
- `TENTATIVE`: 잠정적

---

### 13. `HTTPRequest`

**용도**: HTTP 요청 정보

**필드**:
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `method` | `str` | HTTP 메서드 |
| `url` | `str` | 요청 URL |
| `headers` | `Dict[str, str]` | 요청 헤더 |
| `body` | `Optional[str]` | 요청 본문 |
| `cookies` | `Dict[str, str]` | 쿠키 |

---

### 14. `HTTPResponse`

**용도**: HTTP 응답 정보

**필드**:
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `status_code` | `int` | 상태 코드 |
| `headers` | `Dict[str, str]` | 응답 헤더 |
| `body` | `str` | 응답 본문 (최대 10KB) |
| `elapsed_ms` | `float` | 응답 시간 (밀리초) |

---

### 15. `PluginResult`

**용도**: 플러그인 실행 결과

**필드**:
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `plugin_name` | `str` | 플러그인 이름 |
| `status` | `PluginStatus` | 실행 상태 |
| `findings` | `List[Finding]` | 발견된 취약점 목록 |
| `start_time` | `datetime` | 시작 시간 |
| `end_time` | `datetime` | 종료 시간 |
| `duration_seconds` | `float` | 소요 시간 (초) |
| `urls_scanned` | `int` | 스캔한 URL 수 |
| `requests_sent` | `int` | 보낸 요청 수 |
| `error` | `Optional[PluginError]` | 에러 정보 |
| `metadata` | `Dict[str, Any]` | 추가 메타데이터 |

**PluginStatus Enum**:
- `SUCCESS`: 성공
- `PARTIAL`: 부분 성공
- `FAILED`: 실패
- `SKIPPED`: 건너뜀
- `TIMEOUT`: 타임아웃

---

### 16. `ScanReport`

**용도**: 전체 스캔 리포트

**필드**:
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `scan_id` | `str` | 스캔 고유 ID |
| `target_url` | `str` | 스캔 대상 URL |
| `scanner_version` | `str` | 스캐너 버전 |
| `start_time` | `datetime` | 시작 시간 |
| `end_time` | `datetime` | 종료 시간 |
| `duration_seconds` | `float` | 총 소요 시간 |
| `config` | `ScanConfig` | 사용된 설정 |
| `plugin_results` | `List[PluginResult]` | 플러그인 결과 목록 |
| `summary` | `ScanSummary` | 요약 정보 |
| `metadata` | `ScanMetadata` | 메타데이터 |

---

### 17. `ScanSummary`

**용도**: 스캔 결과 요약

**필드**:
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `total_vulnerabilities` | `int` | 총 취약점 수 |
| `severity_counts` | `Dict[Severity, int]` | 심각도별 개수 |
| `plugin_counts` | `Dict[str, int]` | 플러그인별 개수 |
| `total_urls_scanned` | `int` | 총 스캔된 URL 수 |
| `total_requests` | `int` | 총 요청 수 |
| `success_rate` | `float` | 성공률 (%) |
| `has_critical` | `bool` | Critical 취약점 존재 여부 |
| `has_high` | `bool` | High 취약점 존재 여부 |

---

### 18. `ScanMetadata`

**용도**: 스캔 메타데이터

**필드**:
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `hostname` | `str` | 실행 호스트명 |
| `username` | `str` | 실행 사용자 |
| `python_version` | `str` | Python 버전 |
| `os_info` | `str` | OS 정보 |
| `cli_args` | `Optional[List[str]]` | CLI 인자 (CLI 실행 시) |
| `config_file` | `Optional[str]` | 설정 파일 경로 |

---

## 에러 타입 (`Error Types`)

### 19. `S2NException`

**용도**: 모든 S2N 예외의 베이스 클래스

**필드**:
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `message` | `str` | 에러 메시지 |
| `error_code` | `str` | 에러 코드 |
| `timestamp` | `datetime` | 발생 시간 |
| `context` | `Dict[str, Any]` | 추가 컨텍스트 |

**하위 클래스**:
- `NetworkError`: 네트워크 관련 에러
- `AuthenticationError`: 인증 실패
- `ConfigurationError`: 설정 오류
- `PluginError`: 플러그인 오류
- `CrawlerError`: 크롤러 오류
- `ValidationError`: 입력 검증 오류

---

### 20. `ErrorReport`

**용도**: 에러 정보 리포트

**필드**:
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `error_type` | `str` | 에러 타입 |
| `message` | `str` | 에러 메시지 |
| `traceback` | `Optional[str]` | 스택 트레이스 |
| `timestamp` | `datetime` | 발생 시간 |
| `context` | `Dict[str, Any]` | 에러 컨텍스트 |
| `recoverable` | `bool` | 복구 가능 여부 |
| `retry_count` | `int` | 재시도 횟수 |

---

## 출력 타입 (`Output Types`)

### 21. `JSONOutput`

**용도**: JSON 출력 형식

**구조**:
```json
{
  "scan_id": "uuid",
  "target_url": "http://...",
  "scanner_version": "0.1.0",
  "start_time": "ISO8601",
  "end_time": "ISO8601",
  "duration_seconds": 123.45,
  "summary": { ... },
  "plugin_results": [ ... ],
  "metadata": { ... }
}
```

---

### 22. `ConsoleOutput`

**용도**: 콘솔 출력 데이터

**필드**:
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `mode` | `ConsoleMode` | 출력 모드 |
| `summary_lines` | `List[str]` | 요약 라인 |
| `detail_lines` | `List[str]` | 상세 라인 |
| `progress_info` | `Optional[ProgressInfo]` | 진행 정보 |

---

### 23. `ProgressInfo`

**용도**: 진행 상황 정보

**필드**:
| 필드명 | 타입 | 설명 |
|--------|------|------|
| `current` | `int` | 현재 진행 |
| `total` | `int` | 전체 개수 |
| `percentage` | `float` | 진행률 (%) |
| `message` | `str` | 진행 메시지 |

---

## Enum 타입 정리

### 모든 Enum 타입

`s2n/s2nscanner/interfaces.py`에 정의되어있습니다:

[MAIN branch](https://github.com/504s2n/s2n/blob/main/s2n/s2nscanner/interfaces.py)
[DEV branch](https://github.com/504s2n/s2n/blob/dev/s2n/s2nscanner/interfaces.py)

---

## 사용 예시

### CLI 사용

```bash
s2n scan \
  --url http://target.com \
  --plugin sql --plugin xss \
  --auth basic \
  --username admin \
  --password pass \
  --output results.json \
  --verbose
```

### Python Import 사용

```python
from s2n import Scanner, ScanConfig, PluginConfig, AuthConfig
from s2n.interfaces import Severity, AuthType

# 설정 생성
config = ScanConfig(
    target_url="http://target.com",
    scanner_config=ScannerConfig(crawl_depth=3),
    plugin_configs={
        "sql": PluginConfig(
            enabled=True,
            max_payloads=50
        )
    },
    auth_config=AuthConfig(
        auth_type=AuthType.BASIC,
        username="admin",
        password="pass"
    )
)

# 스캔 실행
scanner = Scanner(config)
report = scanner.scan()

# 결과 처리
print(f"발견된 취약점: {report.summary.total_vulnerabilities}개")
for result in report.plugin_results:
    for finding in result.findings:
        if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
            print(f"[{finding.severity}] {finding.title}")
```

---


이 문서의 모든 타입은 `s2n/s2nscanner/interfaces.py`에 구현됩니다.