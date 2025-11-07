# CLI 실행용
from __future__ import annotations
import sys
import json
import logging
import importlib
from typing import List, Optional, Dict, Any
import click 

import warnings
warnings.filterwarnings("ignore", category=Warning)

from s2n.s2nscanner.http.client import HttpClient
from s2n.s2nscanner.scan_engine import Scanner, ScanReport
from s2n.s2nscanner.crawler import crawl_recursive
from s2n.s2nscanner.auth.dvwa_adapter import DVWAAdapter

# config loader
def load_config(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    try:
        if path.endswith(".json"):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
            # TO-DO: toml/yaml 파일 지원 (추후)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        raise click.ClickException(f"Failed to load config {path}: {e}")
    
def init_logger(verbose: bool, log_file: Optional[str]) -> logging.Logger:
    logger = logging.getLogger("s2n")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if logger.handlers:
        logger.handlers = []
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    logger.addHandler(sh)
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
        logger.addHandler(fh)
    return logger

def filter_plugins_by_name(plugins: List[Any], names: List[str]) -> List[Any]:
    if not names:
        return plugins
    name_set = set(n.lower() for n in names)
    picked = []
    for p in plugins:
        pname = getattr(p, "name", p.__class__.__name__).lower()
        if pname in name_set:
            picked.append(p)
    return picked

@click.group()
@click.option("-c", "--config", "config_path", type=click.Path(), help="설정 파일 경로 (json)")
@click.option("-v", "--verbose", is_flag=True, help="상세 출력 모드")
@click.option("--log-file", type=click.Path(), help="로그 파일 경로")
@click.pass_context
def cli(ctx, config_path, verbose, log_file):
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path
    ctx.obj["config"] = load_config(config_path)
    ctx.obj["verbose"] = verbose
    ctx.obj["log_file"] = log_file
    ctx.obj["logger"] = init_logger(verbose, log_file)

@cli.command("list-plugins")
@click.pass_context
def list_plugins(ctx):
    logger: logging.Logger = ctx.obj["logger"]
    logger.info("Discovering plugins...")
    scanner = Scanner(config=ctx.obj["config"], logger=logger)
    plugins = scanner.discover_plugins()
    if not plugins:
        click.echo("No plugins found.")
        return
    for p in plugins:
        pname = getattr(p, "name", p.__class__.__name__)
        pdesc = getattr(p, "description", getattr(p, "__doc__", "") or "")
        click.echo(f"- {pname}: {pdesc}")

@cli.command("config-show")
@click.pass_context
def config_show(ctx):
    cfg = ctx.obj.get("config") or {}
    click.echo(json.dumps(cfg, indent=2, ensure_ascii=False))

@cli.command("crawl")
@click.option("-u", "--url", required=True, help="타겟 URL")
@click.option("-d", "--depth", default=1, help="크롤링 깊이")
@click.option("-o", "--output", type=click.Path(), help="출력 파일 (json)")
@click.pass_context
def crawl (ctx, url, depth, output):
    logger: logging.Logger = ctx.obj["logger"]
    logger.info("Starting crawl: %s (depth=%d)", url, depth)

    client = HttpClient()
    endpoints = crawl_recursive(base_url=url, client=client, depth=depth)

    click.echo("Discovered endpoints:")
    for e in endpoints:
        click.echo(f" - {e}")
    
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump({"endpoints": endpoints}, f, indent=2)
        logger.info("Saved endpoints to %s", output)


@cli.command("scan")
@click.option("-u", "--url", "urls", required=True, multiple=True, help="타겟 URL")
@click.option("-p", "--plugin", "plugins", multiple=True, help="실행할 플러그인 이름 (여러 개)")
@click.option("-a", "--auth", "auth_type", type=str, help="인증 타입 (예: dvwa)")
@click.option("--username", type=str, help="인증 사용자명")
@click.option("--password", type=str, help="인증 비밀번호")
@click.option("-o", "--output", type=click.Path(), help="결과 출력 파일 (json)")
@click.option("-d", "--depth", default=1, help="크롤링/스캔 깊이")
@click.pass_context
def scan(ctx, urls, plugins, auth_type, username, password, output, depth):
    logger: logging.Logger = ctx.obj["logger"]
    cfg = ctx.obj.get("config") or {}

    scanner = Scanner(
        plugins=None,
        config=cfg,
        auth_adapter=None,
        http_client=None,
        logger=logger,
    )

    discovered = scanner.discover_plugins()
    logger.info("Discovered %d plugins", len(discovered))

    if plugins: 
        discovered = filter_plugins_by_name(discovered, list(plugins))
        if not discovered:
            raise click.ClickException(f"No matching plugins for {plugins}")
        scanner._discovered_plugins = discovered

        if auth_type:
            if auth_type.lower() == "dvwa":
                if not username or not password:
                    raise click.ClickException("DVWA 인증을 위해 --username과 --password를 모두 지정하세요.")
                adapter = DVWAAdapter(base_url=str(urls[0]))
                creds = [(username, password)]
                ok = adapter.ensure_authenticated(creds)
                if not ok:
                    raise click.ClickException("DVWA 로그인 실패")
                scanner.auth_adapter = adapter
                scanner.http_client = adapter.get_client()
                logger.info("DVWA Adapter 인증 완료")
            else:
                raise click.ClickException(f"지원하지 않는 인증 타입입니다: {auth_type}")

        targets = list(urls)
        report: ScanReport = scanner.run(targets)

        results = {
            "targets": report.targets,
            "started_at": report.started_at.isoformat(),
            "finished_at": report.finished_at.isoformat() if report.finished_at else None,
            "findings": [f.__dict__ for f in report.findings],
        }

        if output:
            with open(output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            logger.info("Saved scan results to %s", output)
        else:
            click.echo(json.dumps(results, indent=2, ensure_ascii=False))


        if report.findings:
            logger.warning("Findings detected: exiting with code 1")
            raise SystemExit(1)
        logger.info("No findings: exiting with code 0")
        raise SystemExit(0)
    
if __name__ == "__main__":
    cli()