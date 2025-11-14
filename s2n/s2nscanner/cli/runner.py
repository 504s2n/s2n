
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

# logger 초기화
def init_logger(verbose: bool, log_file: str | None) -> logging.Logger:
    logger = logging.getLogger("s2n")
    logger.setLevel(logging.DEBUG if verbose else logging.WARNING)
    fmt = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger

# CLI entrypoint
@click.group()
def cli():
    ascii_logo = r"""
         _______. ___   .__   __. 
        /       ||__ \  |  \ |  | 
       |   (----`   ) | |   \|  | 
        \   \      / /  |  . `  | 
    .----)   |    / /_  |  |\   | 
    |_______/    |____| |__| \__| 
                              
    
    S2N Web Vulnerability Scanner CLI
    """
    click.echo(ascii_logo)
    click.echo("🔍 Welcome to S2N Scanner! Use --help to explore commands.\n")

# Scan 명령어
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

    # CLIArguments  구성
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

    is_dvwa_auth = (auth or "").lower() == "dvwa"

    # ScanRequest 변환
    request = cliargs_to_scanrequest(args)

    # ScanConfig 구성
    config = build_scan_config(
        request,
        username=args.username,
        password=args.password,
    )

    # 인증/세션 생성
    http_client = None
    auth_adapter = None
    auth_credentials = None

    if request.auth_type and is_dvwa_auth:
        logger.info("DVWA authentication requested.")
        adapter = DVWAAdapter(base_url=request.target_url)
        auth_cfg = config.auth_config
        username = (auth_cfg.username if auth_cfg else None) or args.username or "admin"
        password = (auth_cfg.password if auth_cfg else None) or args.password or "password"
        auth_adapter = adapter
        auth_credentials = [(username, password)]
        ok = adapter.ensure_authenticated(auth_credentials)
        if ok:
            http_client = adapter.get_client()
            logger.info("DVWA 로그인 완료")
        else:
            logger.warning("DVWA 로그인 실패 - 인증 없는 세션으로 계속 진행")

    # ScanContext 생성
    scan_ctx = ScanContext(
        scan_id=f"scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        start_time=datetime.utcnow(),
        config=config,
        http_client=http_client,
        crawler=None,
    )

    # Scanner 실행
    scanner = Scanner(
        config=config,
        scan_context=scan_ctx,
        auth_adapter=auth_adapter,
        auth_credentials=auth_credentials,
        logger=logger,
    )
    report = scanner.scan()

    # 결과 출력
    try:
        output_report(report, config.output_config)
        logger.info("Scan report successfully generated.")
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Failed to output report: %s", exc)

    # verbose 모드: 콘솔 상세 출력
    if verbose and config.output_config.format != OutputFormat.CONSOLE:
        console_output = format_report_to_console(
            report, mode=config.output_config.console_mode
        )
        click.echo("\n===== Scan Summary =====")
        for line in console_output.summary_lines:
            click.echo(line)
        click.echo("========================\n")



if __name__ == "__main__":
    cli()
