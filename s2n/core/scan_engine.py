"""
# 실제 스캐닝 엔진 (플러그인 관리 + 실행))
이 모듈은 s2n의 핵심 로직을 구현합니다.
CLI나 패키지 방식으로 호출될 수 있으며, 
DVWA Adapter 인증 -> HttpClient 공유 -> Plugin 실행 -> ScanReport 반환의 흐름을 관리합니다.
"""

from __future__ import annotations
import logging
import importlib
import pkgutil
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable

from s2n.core.interfaces import Finding, Severity
from s2n.core.s2nscanner.http.client import HttpClient

class ScanReport:
    def __init__(self, targets: List[str]):
        self.targets = targets
        self.findings: List[Finding] = []
        self.started_at = datetime.utcnow()
        self.finished_at: Optional[datetime] = None

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def summerize(self) -> str:
        duration = (
            (self.finished_at - self.started_at).total_seconds()
            if self.finished_at
            else 0.0
        )
        return (
            f"Scan completed: {len(self.finding)} findings "
            f"across {len(self.targets)} targets "
            f"in {duration:.2f}s"
        )


class Scanner:
    # (1) __init__ 초기화
    def __init__(
            self,
            plugins: Optional[List[Any]] = None,
            config: Optional[Dict[str, Any]] = None,
            auth_adapter: Optional[Any] = None,
            http_client: Optional[HttpClient] = None,
            # 아래부터 얘네 쓸/말, 초기값 논의 필요
            concurrency: int = 1,
            timeout: int = 15,
            logger: Optional[logging.Logger] = None,
            on_finding: Optional[Callable[[Finding], None]] = None,
    ):
        self.plugins = plugins or []
        self.config = config or {}
        self.auth_adapter = auth_adapter
        self.http_client = http_client
        self.concurrency = concurrency
        self.timeout = timeout
        self.logger = logger or logging.getLogger("s2n.entry")
        self.on_finding = on_finding

        self._discovered_plugins: List[Any] = []
        self.logger.debug("Scanner Initialized (plugins = %d)", len(self.plugins))

    # (2) discover_plugins - 플러그인 로드
    def discover_plugins(self) -> List[Any]:
        if self.plugins:
            self._discovered_plugins = self.plugins
            self.logger.info("Loaded %d provided plugins.", len(self.plugins))
            return self._discovered_plugins
        
        self.logger.info("Discovering plugins dynamically...")
        try:
            package = "s2n.core.s2nscanner.plugins"
            pkg = importlib.import_module(package)
            for _, modname, _ in pkgutil.iter_modules(pkg.__path__):
                module = importlib.import_module(f"{package}.{modname}")
                if hasattr(module, "Plugin"):
                    try:
                        inst = module.Plugin()
                        self._discovered_plugins.append(inst)
                        self.logger.debug("Plugin loadad: %s", modname)    
                    except Exception:
                        self.logger.exception(f"Failed to instantiate plugin %s", modname)
        except Exception as e:
            self.logger.exception("Plugin discovery failed.: %s", e)
    
        return self._discovered_plugins
    
# (3) _authenticate 인증 관리
    def _authenticate(self, target_url: Optional[str] = None) -> bool:
        if not self.auth_adapter:
            self.logger.debug("No authentication adapter provided. Skipping login.")
            return True
        
        try:
            ok = self.auth_adapter.login()
            if ok:
                self.http_client = getattr(self.auth_adapter, "http", self.http_client)
                self.logger.info("Authentication succeeded via DVWA Adapter.")
                return True
            else:
                self.logger.warning("Authentication failed. Adapter.login returned False.")
                return False
        except Exception as e:
            self.logger.exception(f"Authentication error: {e}")
            return False

    # 문자열 또는 Severity 입력을 받아 Severity enum으로 반환 (기본 MEDIUM) 
    def _normalize_severity(self, val: Any) -> Severity:
        if isinstance(val, Severity):
            return val
        if isinstance(val, str):
            try:
                return Severity(val)
            except ValueError:
                try:
                    return Severity(val.upper())
                except Exception:
                    return Severity.MEDIUM
        return Severity.MEDIUM

    # 플러그인이 반환한 dict를 Finding 인스턴스로 안전히 변환
    def _dict_to_finding(self, plugin_name: str, d: Dict[str, Any], default_url: str) -> Finding:
        fid = d.get("id") or str(uuid.uuid4())
        severity = self._normalize_severity(d.get("severity", Severity.MEDIUM))
        title = d.get("title", "Unnamed finding")
        description = d.get("description", "")
        url = d.get("url", default_url)
        payload = d.get("payload")
        evidence = d.get("evidence")
        return Finding(
            id=fid,
            plugin=plugin_name,
            severity=severity,
            title=title,
            description=description,
            url=url,
            payload=payload,
            evidence=evidence,
        )

    # (4) run_target - 단일 타겟 스캔 (모든 플러그인 순차 실행)
    def run_target(self, target: str) -> List[Finding]:
        self.logger.info(f"Scanning target: {target}")

        if not self._authenticate(target):
            self.logger.error("Authentication failed; skipping target: %s", target)
            return []
        
        if not self.http_client:
            self.http_client = HttpClient(base_url=target)
            self.logger.debug("Created HttpClient for target: %s", target)

        findings: List[Finding] = []

        for plugin in self._discovered_plugins:
            plugin_name = getattr(plugin, "name", plugin.__class__.__name__)
            try:
                if hasattr(plugin, "initialize"):
                    try:
                        plugin.initialize(self.config.get(plugin_name, {}), self.http_client)
                    except TypeError:
                        plugin.initialize()

                #플러그인은 Finding 객체 리스트 또는 dict 리스트를 반환해야 함
                plugin_results = plugin.scan(target, self.http_client)

                if isinstance(plugin_results, (Finding, dict)):
                    plugin_results = [plugin_results]

                for item in plugin_results:
                    if isinstance(item, Finding):
                        f = item
                    elif isinstance(item, dict):
                        f = self._dict_to_finding(plugin_name, item, default_url = target)
                    else:
                        self.logger.warning("Plugin %s returned unsupported result type: %s", plugin_name, type(item))
                        continue

                    findings.append(f)
                    if self.on_finding:
                        try:
                            self.on_finding(f)
                        except Exception:
                            self.logger.exception("on_finding callback raised an exception.")

                self.logger.info("PLugin %s: %d findings", plugin_name, len([x for x in plugin_results if x]))
            except Exception as e:
                self.logger.exception("Plugin %s faild during scan: %s", plugin_name, e)
                continue
            finally:
                if hasattr(plugin, "teardown"):
                    try:
                        plugin.teardown()
                    except Exception:
                        self.logger.debug("Plugin %s teardown failed.", plugin_name)
        
        return findings

    # 여러 타깃을 순회하며 전체 스캔 수행 및 ScanReport 반환
    def run(self, targets:List[str]) -> ScanReport:
        report = ScanReport(targets)
        self.logger.info("Starting scan for %d targets", len(targets))

        self.discover_plugins()

        for target in targets:
            t_findings = self.run_target(target)
            for f in t_findings:
                report.add_finding(f)

        report.finished_at = datetime.utcnow()
        self.logger.info(report.summerize())
        return report
