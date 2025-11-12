# TECH_SPEC.md
**컴포넌트:** `s2n/s2nscanner/plugins/xss`  
**기능명:** XSS Plugin Test Architecture & Implementation  
**작성자:** 정완우  
**협업자:** ChatGPT-5, Claude Sonnet 4.5  
**최종 수정일:** 2025-11-12  
**대상 브랜치:** `dev`  

---

## 🚀 작업 진행 상황 (Commit Tracking)

### Phase 1: 핵심 단위 테스트 (Unit Tests)
```
[+] pytest 환경 구성 (pytest.ini, requirements-test.txt, .gitignore)
    Commit ID: 807251f / Commit Message: test/xss : 1. unit test - pytest 환경 구성

[>] test_fixtures.py 데이터 상수 작성 (HTML/페이로드 샘플)
    Commit ID: ________ / Commit Message: ________________________________________

[>] conftest.py 공통 픽스처 정의 (responses_mock, payload_path 등)
    Commit ID: ________ / Commit Message: ________________________________________

[>] test_xss_unit.py - xss.py 헬퍼 함수 테스트 (_parse_cookies, _finding_to_dict)
    Commit ID: ________ / Commit Message: ________________________________________

[>] test_xss_unit.py - xss_scanner.py 데이터 클래스 테스트 (PayloadResult, Finding)
    Commit ID: ________ / Commit Message: ________________________________________

[>] test_xss_unit.py - FormParser 클래스 테스트
    Commit ID: ________ / Commit Message: ________________________________________

[>] test_xss_unit.py - InputPointDetector 클래스 테스트
    Commit ID: ________ / Commit Message: ________________________________________

[>] test_xss_unit.py - ReflectedScanner 개별 메서드 테스트 (_detect_context, _record)
    Commit ID: ________ / Commit Message: ________________________________________
```

### Phase 2: 통합 테스트 (Integration Tests)
```
[>] test_xss_integration.py - ReflectedScanner 반사형 XSS 전체 플로우 (GET)
    Commit ID: ________ / Commit Message: ________________________________________

[>] test_xss_integration.py - ReflectedScanner 반사형 XSS 전체 플로우 (POST)
    Commit ID: ________ / Commit Message: ________________________________________

[>] test_xss_integration.py - ReflectedScanner CSRF 토큰 처리 테스트
    Commit ID: ________ / Commit Message: ________________________________________

[>] test_xss_integration.py - StoredScanner 저장형 XSS 전체 플로우
    Commit ID: ________ / Commit Message: ________________________________________

[>] test_xss_integration.py - XSSPlugin.run() 통합 테스트
    Commit ID: ________ / Commit Message: ________________________________________
```

### Phase 3: E2E 테스트 및 최적화
```
[>] test_xss_e2e.py - CLI 기본 실행 경로 테스트
    Commit ID: ________ / Commit Message: ________________________________________

[>] test_xss_e2e.py - CLI 사용자 입력/예외 처리 테스트
    Commit ID: ________ / Commit Message: ________________________________________

[>] test_xss_e2e.py - 전체 스캔 시나리오 테스트 (반사형+저장형)
    Commit ID: ________ / Commit Message: ________________________________________

[>] 커버리지 최적화 및 누락 테스트 추가 (목표: 90%+)
    Commit ID: ________ / Commit Message: ________________________________________
```

### Phase 4: 문서화 및 CI/CD
```
[>] README.md 테스트 가이드 작성
    Commit ID: ________ / Commit Message: ________________________________________

[>] GitHub Actions 워크플로우 설정 (.github/workflows/xss-tests.yml)
    Commit ID: ________ / Commit Message: ________________________________________

[>] 최종 커버리지 리포트 생성 및 검증
    Commit ID: ________ / Commit Message: ________________________________________
```

---

## 1. 🎯 목적 및 배경

### 이루고자 하는 목표
- `s2n/s2nscanner/plugins/xss` 플러그인에 대한 **단위(Unit)–통합(Integration)–E2E 테스트 체계**를 완성한다.  
- 테스트를 통해 플러그인 안정성, 재사용성, 회귀 방지 효과를 확보하고  
  향후 **스캐너 전체 테스트 표준 템플릿**으로 확장 가능하도록 설계한다.

### 이루고자 하지 않는 목표
| 항목 | 제외 이유 |
|------|------------|
| 실제 DVWA/OWASP 서버 상호작용 (기본) | 로컬 테스트와 responses 모킹 중심, E2E 확장 시 옵션으로 고려 |
| HTML 렌더링/JS 실행 기반 검증 | Selenium 등 외부 의존성 제거 |
| QA 승인 프로세스 문서화 | 개발용 내부 지침 문서에 초점 |

---

## 2. 📁 디렉토리 구조

```
s2n/s2nscanner/plugins/xss/
├── xss.py
├── xss_scanner.py
├── xss_payloads.json
├── conftest.py                  # 공통 픽스처 정의
├── test_xss_unit.py            # 단위 테스트 (xss.py 헬퍼 + xss_scanner 개별 메서드)
├── test_xss_integration.py     # 통합 테스트
├── test_xss_e2e.py             # E2E 테스트
└── test_fixtures.py            # 데이터 상수 (HTML/Payload 샘플)
```

---

## 3. 🧩 테스트 아키텍처 개요

| 구분 | 설명 | 모킹 정책 |
|------|------|----------|
| **단위(Unit)** | 헬퍼 함수, 내부 로직, 개별 메서드 단위 검증 | 최소 모킹 (필요시만) |
| **통합(Integration)** | XSSPlugin ↔ ReflectedScanner ↔ HttpClient 흐름 검증 | HTTP만 모킹, Scanner 실제 실행 |
| **E2E** | CLI 기반 실행 시 플러그인 전체 동작 확인 | input() 모킹, CLI 함수 실제 실행 |
| **픽스처 관리** | `test_fixtures.py` → 데이터만, `conftest.py` → 픽스처 함수 정의 |  |

### 테스트 커버리지 목표
- **전체 90–95%**  
  - `xss.py`: 100%  
  - `xss_scanner.py`: ≥90%  
  - CLI: ≥80% (예외 처리 중심)

---

## 4. ⚙️ 실행 및 모킹 정책

| 구분 | 정책 | 비고 |
|------|------|------|
| **Scanner 실행** | 통합 테스트에서는 ReflectedScanner 실제 실행 | core 로직 검증 목적 |
| **HTTP 요청** | responses 라이브러리로 완전 모킹 | 외부 요청 차단 |
| **페이로드 파일 접근** | 실제 경로 사용 (`tmp_path_factory` 생성) | pytest fixture에서 session 스코프로 주입 |
| **DVWA 연동** | 기본 테스트는 모킹, E2E 확장 시 옵션 고려 | `@pytest.mark.dvwa` (향후) |

### 모킹 일관성 원칙
- **단위 테스트**: 테스트 대상 컴포넌트만 실행, 의존성은 최소 모킹
- **통합 테스트**: HTTP 계층만 모킹, 스캐너 로직은 실제 실행
- **E2E 테스트**: 사용자 입력(input)만 모킹, 전체 실행 경로 검증

---

## 5. 🧱 conftest.py 구성 원칙

| 픽스처명 | 설명 | 스코프 |
|-----------|-------|--------|
| `responses_mock` | HTTP 요청 모킹용 컨텍스트 | function |
| `mock_http_client` | HttpClient 대체 객체 | function |
| `payload_path` | 임시 payload JSON 파일 경로 (tmp_path_factory 사용) | session |
| `sample_payloads` | test_fixtures 내 상수 데이터 | session |
| `simple_html` / `form_html` | HTML 응답 샘플 | session |

> **중요:**  
> - 모든 픽스처는 명시적으로 `@pytest.fixture(scope="...")`를 지정한다.  
> - 공통적으로 사용되는 픽스처만 conftest.py에 두고, 개별 테스트 특화 픽스처는 해당 test 파일 내부에서 정의한다.  
> - `tmp_path`는 function 스코프, `tmp_path_factory`는 session 스코프 사용

---

## 6. 🧪 test_fixtures.py 정책

- 순수 **데이터 상수(Python literal)** 로 구성  
- I/O가 필요한 경우 conftest.py에서 tmp_path_factory를 통해 임시 파일 생성 후 주입
- 예시:

```python
# test_fixtures.py
"""테스트에서 사용할 데이터 상수"""

SAMPLE_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><img src=x onerror=alert(1)>",
]

SIMPLE_HTML = "<html><body><input name='q'></body></html>"

FORM_WITH_CSRF_HTML = """
<form action="/submit" method="POST">
    <input type="hidden" name="csrf_token" value="abc123">
    <input type="text" name="comment">
</form>
"""
```

---

## 7. 🧩 테스트 파일별 역할

| 파일 | 주요 목적 |
|------|-----------|
| `test_xss_unit.py` | `xss.py` 헬퍼 함수 (_parse_cookies, _finding_to_dict) + `xss_scanner.py` 개별 메서드 검증 |
| `test_xss_integration.py` | XSSPlugin.run()과 스캐너 간 상호작용, 결과 객체 구조 검증 |
| `test_xss_e2e.py` | CLI 실행 흐름, 사용자 입력/예외 처리 검증 (sys.exit patch) |
| `test_fixtures.py` | 공용 데이터 상수 관리 |

---

## 8. 🔖 pytest 마커 정책

### 마커 정의 (pytest.ini)

```ini
[pytest]
markers =
    unit: 단위 테스트
    integration: 통합 테스트
    e2e: 전체 실행 테스트
    slow: 대용량 페이로드/모킹 제외 시나리오
```

### 마커 사용 예시

```python
@pytest.mark.unit
def test_parse_cookie_valid():
    ...

@pytest.mark.integration
@pytest.mark.slow
def test_reflected_xss_full_scan():
    ...
```

**규칙:**
- 모든 테스트는 반드시 적어도 하나의 마커(unit/integration/e2e) 포함
- `slow`는 E2E 중 실제 네트워크/페이로드 대량 수행 시에만 사용

---

## 9. 🧾 Phase 기반 단계 구분 및 완료 기준

| Phase | 목표 | 주요 산출물 | 완료 기준 (정량 + 정성) |
|-------|------|-------------|------------------------|
| **Phase 1 — Unit** | 헬퍼 함수 및 ReflectedScanner 단위 검증 | test_xss_unit.py, conftest.py 초기 버전 | • 단위 테스트 15+ 케이스<br>• 커버리지 70%+<br>• pytest 실행 성공 |
| **Phase 2 — Integration** | Plugin ↔ Scanner 연동 검증 | test_xss_integration.py | • 통합 테스트 10+ 케이스<br>• 커버리지 85%+<br>• run() 결과 객체 구조 확인 |
| **Phase 3 — E2E** | CLI 및 전체 스캐너 실행 경로 검증 | test_xss_e2e.py | • E2E 테스트 5+ 케이스<br>• 전체 커버리지 90%+<br>• CLI 입력/예외 처리 검증 |
| **Phase 4 — CI 준비** | pytest.ini, markers, 커버리지 리포트 구성 | coverage.xml, pytest.ini, README | • GitHub Actions 성공<br>• 문서화 완료<br>• 커버리지 리포트 생성 |

---

## 10. 🧰 테스트 실행 방법

### 로컬 실행

```bash
# 전체 테스트 실행
PYTHONPATH=. pytest -q --disable-warnings

# 범위별 실행
pytest -m unit
pytest -m integration
pytest -m e2e

# 커버리지 측정
pytest --cov=s2n.s2nscanner.plugins.xss --cov-report=term-missing

# 특정 파일만 실행
pytest test_xss_unit.py -v

# 병렬 실행 (pytest-xdist 설치 필요)
pytest -n auto
```

---

## 11. 🧩 Appendix: GitHub Actions 예시

```yaml
name: XSS Plugin Tests
on:
  push:
    branches: [ "dev" ]
  pull_request:
    branches: [ "dev" ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      
      - name: Install dependencies
        run: |
          pip install -r requirements-test.txt
      
      - name: Run tests with coverage
        run: |
          pytest -q --maxfail=1 --disable-warnings \
            --cov=s2n.s2nscanner.plugins.xss \
            --cov-report=xml \
            --cov-report=term-missing
      
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml
          fail_ci_if_error: true
```

**CI 정책:**
- PR merge 시 테스트 필수 통과
- 커버리지 90% 미만 시 경고

---

## 12. ✅ 리뷰 체크리스트

| 항목 | 질문 |
|------|------|
| 코드 구조 | 각 테스트가 명확한 목적(단위/통합/E2E)을 갖는가? |
| 픽스처 관리 | conftest와 개별 테스트 간 중복이 없는가? |
| 모킹 일관성 | responses 모킹이 올바르게 작동하는가? |
| 커버리지 | 핵심 함수와 에러 핸들링 경로가 모두 포함되는가? |
| 실행 속도 | slow 마커 테스트를 제외하고 3초 내 완료되는가? |
| 문서화 | 각 테스트의 목적이 docstring으로 명확히 설명되어 있는가? |

---

## 13. 📅 유지보수 및 확장 계획

| 항목 | 계획 |
|------|------|
| 페이로드 확장 | 카테고리별 50–70개 샘플 유지, 신규 XSS vector 추가 |
| 스캐너 기능 확장 | Stored/DOM 기반 테스트 추가 시 구조 동일하게 재사용 |
| CI 통합 강화 | 전체 플러그인 레벨 테스트 병합 시 pytest marker 기반 병렬 실행 |
| 보고서 검증 | PluginResult → JSON 직렬화 테스트 추가 예정 |
| DVWA 통합 테스트 | `@pytest.mark.dvwa`로 선택적 실제 서버 테스트 구현 (Phase 5) |

---

## 📘 결론

본 문서는 `s2n/s2nscanner/plugins/xss`의 테스트 구현을 위한  
**공식 기술 지침서(Technical Specification)** 로,  
개발자 간 일관된 테스트 작성 패턴을 확립하고,  
CI·커버리지·E2E 실행까지 아우르는 실질적 테스트 표준을 제시한다.

---

**작성자:** 정완우  
**협업 엔지니어:** ChatGPT-5 / Claude Sonnet 4.5  
**최종 승인일:** 2025-11-12  
**문서 버전:** 2.0 (최종)

---