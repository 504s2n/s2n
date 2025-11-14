from __future__ import annotations
from datetime import datetime
import logging
import click

from s2n.s2nscanner.interfaces import CLIArguments, ScanContext
from s2n.s2nscanner.cli.mapper import cliargs_to_scanrequest
from s2n.s2nscanner.cli.config_builder import build_scan_config
from s2n.s2nscanner.auth.dvwa_adapter import DVWAAdapter
from s2n.s2nscanner.scan_engine import Scanner
from s2n.s2nscanner.report import (
    output_report,
    OutputFormat,
    format_report_to_console,
)

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ============================================================
# Logger 초기화
# ============================================================
def init_logger(verbose: bool, log_file: str | None) -> logging.Logger:
    logger = logging.getLogger("s2n")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


# ============================================================
# CLI Root
# ============================================================
@click.group()
def cli():
    ascii_logo = r"""
    (`-').->        <-. (`-')_
    ( OO)_             \( OO) )
    (_)--\_)  .----. ,--./ ,--/
    /    _ / \_,-.  ||   \ |  |
    \_..`--.    .' .'|  . '|  |)
    .-._)   \ .'  /_ |  |\    |
    \       /|      ||  | \   |
    `-----' `------'`--'  `--'
    
    S2N Web Vulnerability Scanner CLI
    """
    click.echo(ascii_logo)
    click.echo("🔍 Welcome to S2N Scanner! Use --help to explore commands.\n")


# ============================================================
# scan 명령어
# ============================================================
@cli.command("scan")
@click.option("-u", "--url", required=True, help="스캔 대상 URL")
@click.option("-p", "--plugin", multiple=True, help="사용할 플러그인 이름 (복수 선택 가능)")
@click.option("-a", "--auth", help="인증 타입 (NONE, BASIC, BEARER, DVWA 등)")
@click.option("--username", help="인증용 사용자명")
@click.option("--password", help="인증용 비밀번호")
@click.option("-o", "--output", help="결과 출력 파일 경로 (예: result.json)")
@click.option("-v", "--verbose", is_flag=True, help="상세 로그 출력")
@click.option("--log-file", help="로그 파일 경로")
def scan(url, plugin, auth, username, password, output, verbose, log_file):
    logger = init_logger(verbose, log_file)
    logger.info("Starting scan for %s", url)

    # --------------------------------------------------------
    # CLIArguments 구성
    # --------------------------------------------------------
    args = CLIArguments(
        url=url,
        plugin=list(plugin),
        auth=auth,
        username=username,
        password=password,
        output=output,
        verbose=verbose,
        log_file=log_file,
    )

    request = cliargs_to_scanrequest(args)
    config = build_scan_config(request, username=username, password=password)

    # --------------------------------------------------------
    # 인증 처리 (DVWA)
    # --------------------------------------------------------
    http_client = None
    auth_adapter = None
    auth_credentials = None

    if (auth or "").lower() == "dvwa":
        logger.info("DVWA authentication requested.")
        adapter = DVWAAdapter(base_url=request.target_url)
        username = username or "admin"
        password = password or "password"

        auth_adapter = adapter
        auth_credentials = [(username, password)]

        if adapter.ensure_authenticated(auth_credentials):
            http_client = adapter.get_client()
            logger.info("DVWA 로그인 완료")
        else:
            logger.warning("DVWA 로그인 실패 - 인증 없이 진행")

    # --------------------------------------------------------
    # ScanContext 생성
    # --------------------------------------------------------
    scan_ctx = ScanContext(
        scan_id=f"scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        start_time=datetime.utcnow(),
        config=config,
        http_client=http_client,
        crawler=None,
    )

    scanner = Scanner(
        config=config,
        scan_context=scan_ctx,
        auth_adapter=auth_adapter,
        auth_credentials=auth_credentials,
        logger=logger,
    )

    # --------------------------------------------------------
    # Scan 실행 + Duration 계산
    # --------------------------------------------------------
    start = datetime.utcnow()
    report = scanner.scan()
    end = datetime.utcnow()

    duration = (end - start).total_seconds()

    # --------------------------------------------------------
    # Report 출력
    # --------------------------------------------------------
    try:
        output_report(report, config.output_config)
        logger.info("Scan report successfully generated.")
    except Exception as exc:
        logger.exception("Failed to output report: %s", exc)

    # --------------------------------------------------------
    # Rich Summary (Verbose)
    # --------------------------------------------------------
    if verbose:
        table = Table(
            title="🚀 S2N Scan Summary",
            title_style="bold magenta",
            box=box.SIMPLE_HEAVY,
            show_header=False,
            padding=(0, 1),
        )

        # Target URL (config 또는 Report의 target_url)
        target_url = getattr(report, "target_url", None) or request.target_url

        # Finding 개수
        total_findings = sum(len(p.findings) for p in report.plugin_results)

        table.add_row("🎯 Target URL", target_url)
        table.add_row("🆔 Scan ID", report.scan_id)
        table.add_row("⏱ Duration", f"{report.duration_seconds:.2f} seconds")
        table.add_row("🧩 Plugins Loaded", str(len(report.plugin_results)))
        table.add_row("🔎 Findings Detected", str(total_findings))
        table.add_row("📄 Output Format", config.output_config.format.value)

        console.print("\n")
        console.print(table)
        console.print("\n")


if __name__ == "__main__":
    cli()