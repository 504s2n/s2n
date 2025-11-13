from __future__ import annotations
from types import SimpleNamespace
from datetime import datetime
import logging

import pytest 
from click.testing import CliRunner

from s2n.s2nscanner.cli import runner as runner_mod


# Fake ScanReport (runner가 기대하는 구조와 동일하게)
class FakeScanReport:
    def __init__(self, scan_id, started_at):
        self.scan_id = scan_id
        self.started_at = started_at
        self.finished_at = datetime.utcnow()
        self.findings = []
        self.metadata = {}

# FakeScanner
class FakeScanner:
    def __init__(self, config, scan_context, auth_adapter=None, logger=None, **kwargs):
        self.config = config
        self.scan_context = scan_context
        self.auth_adapter = auth_adapter
        self.logger = logger

    def scan(self):
        return FakeScanReport(
            scan_id=self.scan_context.scan_id,
            started_at=self.scan_context.start_time,
        )

# Fake DVWA Adapter
class FakeDVWAAdapter:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.auth_called_with = None
        self.client = object()
        self._ensure_ok = True
    
    def ensure_authenticated(self, credentials):
        self.auth_called_with = credentials
        return self._ensure_ok
    
    def get_client(self):
        return self.client


# Fixtures
@pytest.fixture()
def cli_runner():
    return CliRunner()

@pytest.fixture()
def fake_common(monkeypatch):
    root = logging.getLogger("s2n")
    root.handlers.clear()

    # fake cliargs_to_scanrequest
    def fake_cliargs_to_scanrequests(args):
        return SimpleNamespace(
            target_url=args.url,
            auth_type=None,
            username=args.username,
            password=args.password,
        )
    monkeypatch.setattr(runner_mod, "cliargs_to_scanrequest", fake_cliargs_to_scanrequests)

    # fake build_scan_config
    class FakeOutputConfig:
        def __init__(self):
            self.format = runner_mod.OutputFormat.JSON
            self.console_mode = "SUMMARY"

    def fake_build_scan_config(request, **kwargs):
        return SimpleNamespace(
            auth_config=None,
            output_config=FakeOutputConfig(),
        )
    
    monkeypatch.setattr(runner_mod, "build_scan_config", fake_build_scan_config)

    # Fake Scanner
    monkeypatch.setattr(runner_mod, "Scanner", FakeScanner)

    # Fake DVWA Adapter
    monkeypatch.setattr(runner_mod, "DVWAAdapter", FakeDVWAAdapter)

    # Fake output_report
    called = {}
    def fake_output_report(report, output_config):
        called["report"] = report
        called["output_config"] = output_config
    monkeypatch.setattr(runner_mod, "output_report", fake_output_report)

    return {"output_called": called}


# Tests

def test_scan_no_auth_basic_flow(cli_runner, fake_common):
    result = cli_runner.invoke(
        runner_mod.scan,
        [
            "--url", "http://example.com",
            "--plugin", "oscommand",
            "--output", "result.json",
            # verbose 제거 → format_report_to_console 호출 방지
        ],
    )

    assert result.exit_code == 0, f"CLI failed: {result.output}"
    assert "report" in fake_common["output_called"]
    assert "output_config" in fake_common["output_called"]


def test_scan_with_dvwa_auth(cli_runner, monkeypatch, fake_common):

    class FakeAuthType:
        def __init__(self, name):
            self.name = name

    def fake_cliargs_to_scanrequest(args):
        return SimpleNamespace(
            target_url=args.url,
            auth_type=FakeAuthType("DVWA"),
            username=args.username,
            password=args.password,
        )
    monkeypatch.setattr(runner_mod, "cliargs_to_scanrequest", fake_cliargs_to_scanrequest)

    created = []

    class TrackingDVWAAdapter(FakeDVWAAdapter):
        def __init__(self, base_url):
            super().__init__(base_url)
            created.append(self)

    monkeypatch.setattr(runner_mod, "DVWAAdapter", TrackingDVWAAdapter)

    result = cli_runner.invoke(
        runner_mod.scan,
        [
            "--url", "http://localhost/dvwa",
            "--plugin", "oscommand",
            "--auth", "dvwa",
            "--username", "admin",
            "--password", "password",
            "--output", "result.json",
        ],
    )

    assert result.exit_code == 0, f"CLI failed: {result.output}"
    assert created, "DVWAAdapter was not created"

    adapter = created[0]
    assert adapter.auth_called_with == [("admin", "password")]


def test_scan_output_report_error_does_not_crash(cli_runner, monkeypatch, fake_common):

    def exploding_output_report(report, output_config):
        raise RuntimeError("boom")

    monkeypatch.setattr(runner_mod, "output_report", exploding_output_report)

    result = cli_runner.invoke(
        runner_mod.scan,
        [
            "--url", "http://example.com",
            "--plugin", "oscommand",
            "--output", "result.json",
        ],
    )

    assert result.exit_code == 0, f"CLI should not crash: {result.output}"