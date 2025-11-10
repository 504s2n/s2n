"""
Finding 처리 모듈
이전 단계에서 생성된 Finding 객체들을 받아서
다음 단계에 필요한 객체를 생성하는 함수들입니다.

함수 매개 변수와 함수 반환 타입 
Args & Returns Types:
- create_plugin_result -> PluginResult
- create_scan_summary -> ScanSummary
- create_scan_report -> ScanReport
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from collections import Counter

from s2n.s2nscanner.interfaces import (
    Finding,
    PluginResult,
    PluginStatus,
    PluginError,
    ScanSummary,
    ScanReport,
    ScanConfig,
    ScanMetadata,
    Severity,
)


def create_plugin_result(
    plugin_name: str,
    findings: List[Finding],
    start_time: datetime,
    end_time: Optional[datetime] = None,
    status: PluginStatus = PluginStatus.SUCCESS,
    urls_scanned: int = 0,
    requests_sent: int = 0,
    error: Optional[PluginError] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> PluginResult:
    """
    Finding 리스트와 플러그인 실행 정보를 받아 PluginResult를 생성합니다.

    Args:
        plugin_name: 플러그인 이름
        findings: 발견된 취약점 리스트
        start_time: 플러그인 실행 시작 시간
        end_time: 플러그인 실행 종료 시간 (None이면 현재 시간 사용)
        status: 플러그인 실행 상태
        urls_scanned: 스캔한 URL 개수
        requests_sent: 전송한 요청 개수
        error: 발생한 에러 (있는 경우)
        metadata: 추가 메타데이터

    Returns:
        PluginResult: 생성된 플러그인 실행 결과
    """
    if end_time is None:
        end_time = datetime.now()
    
    duration_seconds = (end_time - start_time).total_seconds()
    
    return PluginResult(
        plugin_name=plugin_name,
        status=status,
        findings=findings,
        start_time=start_time,
        end_time=end_time,
        duration_seconds=duration_seconds,
        urls_scanned=urls_scanned,
        requests_sent=requests_sent,
        error=error,
        metadata=metadata or {},
    )


def create_scan_summary(plugin_results: List[PluginResult]) -> ScanSummary:
    """
    PluginResult 리스트를 받아 ScanSummary를 생성합니다.

    Args:
        plugin_results: 플러그인 실행 결과 리스트

    Returns:
        ScanSummary: 생성된 스캔 요약 정보
    """
    all_findings: List[Finding] = []
    total_urls_scanned = 0
    total_requests = 0
    successful_plugins = 0
    
    for result in plugin_results:
        all_findings.extend(result.findings)
        total_urls_scanned += result.urls_scanned
        total_requests += result.requests_sent
        if result.status == PluginStatus.SUCCESS:
            successful_plugins += 1
    
    # 심각도별 카운트
    severity_counts: Dict[Severity, int] = Counter(
        finding.severity for finding in all_findings
    )
    
    # 플러그인별 카운트
    plugin_counts: Dict[str, int] = Counter(
        finding.plugin for finding in all_findings
    )
    
    # 성공률 계산
    success_rate = (
        (successful_plugins / len(plugin_results) * 100.0)
        if plugin_results else 0.0
    )
    
    # Critical/High 취약점 존재 여부
    has_critical = Severity.CRITICAL in severity_counts
    has_high = Severity.HIGH in severity_counts
    
    return ScanSummary(
        total_vulnerabilities=len(all_findings),
        severity_counts=dict(severity_counts),
        plugin_counts=dict(plugin_counts),
        total_urls_scanned=total_urls_scanned,
        total_requests=total_requests,
        success_rate=success_rate,
        has_critical=has_critical,
        has_high=has_high,
    )


def create_scan_report(
    scan_id: str,
    target_url: str,
    scanner_version: str,
    start_time: datetime,
    end_time: datetime,
    config: ScanConfig,
    plugin_results: List[PluginResult],
    metadata: Optional[ScanMetadata] = None,
) -> ScanReport:
    """
    PluginResult 리스트와 스캔 메타데이터를 받아 ScanReport를 생성합니다.

    Args:
        scan_id: 스캔 고유 ID
        target_url: 스캔 대상 URL
        scanner_version: 스캐너 버전
        start_time: 스캔 시작 시간
        end_time: 스캔 종료 시간
        config: 사용된 스캔 설정
        plugin_results: 플러그인 실행 결과 리스트
        metadata: 스캔 메타데이터 (선택)

    Returns:
        ScanReport: 생성된 전체 스캔 리포트
    """
    duration_seconds = (end_time - start_time).total_seconds()
    
    # ScanSummary 생성
    summary = create_scan_summary(plugin_results)
    
    return ScanReport(
        scan_id=scan_id,
        target_url=target_url,
        scanner_version=scanner_version,
        start_time=start_time,
        end_time=end_time,
        duration_seconds=duration_seconds,
        config=config,
        plugin_results=plugin_results,
        summary=summary,
        metadata=metadata,
    )

