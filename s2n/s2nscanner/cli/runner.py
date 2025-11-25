from __future__ import annotations
import click
from datetime import datetime

from s2n.s2nscanner.interfaces import CLIArguments, ScanContext, ProgressInfo, PluginStatus
from s2n.s2nscanner.cli.mapper import cliargs_to_scanrequest
from s2n.s2nscanner.cli.config_builder import build_scan_config
from s2n.s2nscanner.auth.dvwa_adapter import DVWAAdapter
from s2n.s2nscanner.scan_engine import Scanner
from s2n.s2nscanner.report import output_report, OutputFormat
from s2n.s2nscanner.logger import init_logger

from rich.console import Console
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich import box

console = Console()


# CLI Root
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


# scan 명령어
@cli.command("scan")
@click.option("-u", "--url", required=True, help="스캔 대상 URL")
@click.option(
    "-p", "--plugin", multiple=True, help="사용할 플러그인 이름 (복수 선택 가능)"
)
@click.option("-a", "--auth", help="인증 타입 (NONE, BASIC, BEARER, DVWA 등)")
@click.option("--username", help="인증용 사용자명")
@click.option("--password", help="인증용 비밀번호")
@click.option("-o", "--output", help="결과 출력 파일 경로 (예: result.json)")
@click.option(
    "--output-format",
    type=click.Choice([fmt.value for fmt in OutputFormat], case_sensitive=False),
    default=OutputFormat.JSON.value,
    show_default=True,
    help="결과 출력 형식 (JSON, HTML, CSV, CONSOLE, MULTI)",
)
@click.option("-v", "--verbose", is_flag=True, help="상세 로그 출력")
@click.option("--log-file", help="로그 파일 경로")
def scan(url, plugin, auth, username, password, output, output_format, verbose, log_file):
    logger = init_logger(verbose, log_file)
    logger.info("Starting scan for %s", url)

    # CLIArguments 구성
    args = CLIArguments(
        url=url,
        plugin=list(plugin),
        auth=auth,
        username=username,
        password=password,
        output=output,
        output_format=output_format,
        verbose=verbose,
        log_file=log_file,
    )

    request = cliargs_to_scanrequest(args)
    config = build_scan_config(request, username=username, password=password)

    # 인증 처리 (DVWA)
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

    # ScanContext 생성
    scan_ctx = ScanContext(
        scan_id=f"scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        start_time=datetime.utcnow(),
        config=config,
        http_client=http_client,
        crawler=None,
    )

    # 진행률 UI 준비
    progress = Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None, complete_style="green", finished_style="magenta"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
        auto_refresh=False,
    )
    progress_task = progress.add_task("🧭 스캔 준비 중", total=1)

    def on_progress(info: ProgressInfo):
        total = info.total or 1
        progress.update(
            progress_task,
            total=total,
            completed=info.current,
            description=info.message,
            refresh=True,
        )

    scanner = Scanner(
        config=config,
        scan_context=scan_ctx,
        auth_adapter=auth_adapter,
        auth_credentials=auth_credentials,
        logger=logger,
        on_progress=on_progress,
    )

    # Scan 실행 + Duration 계산
    with progress:
        start = datetime.utcnow()
        report = scanner.scan()
        end = datetime.utcnow()
        progress.update(progress_task, completed=progress.tasks[0].total, description="🏁 스캔 완료")

    # Report 출력
    try:
        output_report(report, config.output_config)
        logger.info("Scan report successfully generated.")
    except Exception as exc:
        logger.exception("Failed to output report: %s", exc)

    # Rich Summary
    target_url = getattr(report, "target_url", None) or request.target_url
    total_findings = sum(len(p.findings) for p in report.plugin_results)

    summary_table = Table(
        title="🚀 S2N Scan Summary",
        title_style="bold magenta",
        box=box.SIMPLE_HEAVY,
        show_header=False,
        padding=(0, 1),
    )
    summary_table.add_row("🎯 Target URL", f"[bold]{target_url}[/]")
    summary_table.add_row("🆔 Scan ID", report.scan_id)
    summary_table.add_row("⏱ Duration", f"{report.duration_seconds:.2f} seconds")
    summary_table.add_row("🧩 Plugins Loaded", str(len(report.plugin_results)))
    summary_table.add_row("🔎 Findings Detected", f"[bold yellow]{total_findings}[/]")
    summary_table.add_row("📄 Output Format", config.output_config.format.value)

    status_styles = {
        PluginStatus.SUCCESS: "green",
        PluginStatus.PARTIAL: "yellow",
        PluginStatus.FAILED: "red",
        PluginStatus.SKIPPED: "cyan",
        PluginStatus.TIMEOUT: "magenta",
    }
    status_icons = {
        PluginStatus.SUCCESS: "✅",
        PluginStatus.PARTIAL: "🟡",
        PluginStatus.FAILED: "❌",
        PluginStatus.SKIPPED: "⏩",
        PluginStatus.TIMEOUT: "⏰",
    }

    plugin_table = Table(
        title="🧩 Plugin Results",
        title_style="bold cyan",
        box=box.MINIMAL_HEAVY_HEAD,
        header_style="bold white",
    )
    plugin_table.add_column("Plugin")
    plugin_table.add_column("Status", justify="center")
    plugin_table.add_column("Findings", justify="right")
    plugin_table.add_column("Duration", justify="right")
    plugin_table.add_column("Note")

    for pr in report.plugin_results:
        status_color = status_styles.get(pr.status, "white")
        icon = status_icons.get(pr.status, "ℹ️")
        note = "-"
        if getattr(pr, "metadata", None):
            note = pr.metadata.get("reason", note)
        if pr.error:
            note = pr.error.message

        plugin_table.add_row(
            f"{icon} {pr.plugin_name}",
            f"[{status_color}]{pr.status.value}[/{status_color}]",
            str(len(pr.findings)),
            f"{pr.duration_seconds:.2f}s",
            note or "-",
        )

    console.print("\n")
    console.print(summary_table)
    console.print(plugin_table)
    console.print("\n")


if __name__ == "__main__":
    cli()
