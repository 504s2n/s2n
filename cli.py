# CLI 실행용
from __future__ import annotations
import sys
import json
import logging
import importlib
from typing import List, Optional, Dict, Any
import click 
from dataclasses import asdict

import warnings
warnings.filterwarnings("ignore", category=Warning)

from s2n.s2nscanner.http.client import HttpClient
from s2n.s2nscanner.scan_engine import Scanner, ScanReport
from s2n.s2nscanner.crawler import crawl_recursive
from s2n.s2nscanner.auth.dvwa_adapter import DVWAAdapter
from s2n.s2nscanner.interfaces import Finding, Severity

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

    # URL 확보
    if urls and len(urls) > 0:
        target = urls[0]
    else:
        target = click.prompt("테스트할 대상 URL을 입력하세요", type=str)
    logger.info("Target URL: %s", target)

    scanner = Scanner(
        plugins=None,
        config=cfg,
        auth_adapter=None,
        http_client=None,
        logger=logger,
    )

    discovered = scanner.discover_plugins()
    logger.info("Discovered %d plugins", len(discovered))

    # 결과 저장용 리스트
    findings: List[Finding] = []
    started_at = datetime.utcnow().isoformat() if hasattr(datetime, "utcnow") else None

    
    # --- 1) brute_force 먼저 실행 (플러그인에 있으면) ---
    try:
        bf_plugins = [p for p in discovered if getattr(p, "name", "").lower() == "brute_force"]
        if bf_plugins:
            bf = bf_plugins[0]
            logger.info("Running brute_force before authentication (results will be stored).")
            try:
                raw = bf.run(target)
                # raw는 dict 리스트를 반환한다고 가정
                for i, r in enumerate(raw or []):
                    sev_val = r.get("severity", "INFO") if isinstance(r, dict) else "INFO"
                    try:
                        sev = Severity(sev_val)
                    except Exception:
                        sev = Severity.INFO
                    f = Finding(
                        id=r.get("id", f"bf-{i}") if isinstance(r, dict) else f"bf-{i}",
                        plugin=getattr(bf, "name", "brute_force"),
                        severity=sev,
                        title=r.get("title", "Brute force finding") if isinstance(r, dict) else "Brute force finding",
                        description=r.get("description", "") if isinstance(r, dict) else "",
                        url=r.get("url", target) if isinstance(r, dict) else target,
                        payload=r.get("payload") if isinstance(r, dict) else None,
                        evidence=r.get("evidence") if isinstance(r, dict) else None,
                    )
                    findings.append(f)
                logger.info("brute_force finished (%d findings)", len(raw or []))
            except Exception as e:
                logger.exception("brute_force plugin error (continuing): %s", e)
        else:
            logger.debug("No brute_force plugin discovered; skipping brute step.")
    except Exception as e:
        logger.exception("Error while attempting brute_force step (continuing): %s", e)

    # --- 2) DVWA 로그인(필요시) ---
    if "dvwa" in (target or "").lower():
        logger.info("DVWA target detected: attempting authentication via DVWAAdapter")
        # 우선 전달된 username/password 없으면 프롬프트
        dvwa_user = username or click.prompt("DVWA username", default="admin")
        dvwa_pass = password or click.prompt("DVWA password", hide_input=True)
        try:
            adapter = DVWAAdapter(base_url=target)
            ok = adapter.ensure_authenticated([(dvwa_user, dvwa_pass)])
            if ok:
                logger.info("DVWA 로그인 완료")
                scanner.auth_adapter = adapter
                scanner.http_client = adapter.get_client()
            else:
                logger.warning("DVWA 로그인 실패: 계속 진행하되 인증이 필요한 플러그인은 실패할 수 있습니다")
        except Exception as e:
            logger.exception("DVWA adapter error (continuing without auth): %s", e)

    # --- 3) 나머지 플러그인 실행 (brute_force는 이미 수행했으니 건너뜀) ---
    for p in discovered:
        pname = getattr(p, "name", p.__class__.__name__).lower()
        if pname == "brute_force":
            continue
        if plugins:
            # 사용자가 -p 옵션으로 특정 플러그인만 실행 요청했으면 필터링
            if pname not in [x.lower() for x in plugins]:
                logger.debug("Skipping plugin %s due to -p filter", pname)
                continue
        logger.info("Running plugin: %s", pname)
        try:
            if not hasattr(p, "run"):
                logger.debug("plugin %s has no run(): skipping", pname)
                continue
            raw = p.run(target)
            for i, r in enumerate(raw or []):
                # r은 dict-like 예상
                if isinstance(r, Finding):
                    findings.append(r)
                    continue
                sev_val = r.get("severity", "INFO") if isinstance(r, dict) else "INFO"
                try:
                    sev = Severity(sev_val)
                except Exception:
                    sev = Severity.INFO
                f = Finding(
                    id=r.get("id", f"{pname}-{i}") if isinstance(r, dict) else f"{pname}-{i}",
                    plugin=pname,
                    severity=sev,
                    title=r.get("title", f"{pname} finding") if isinstance(r, dict) else f"{pname} finding",
                    description=r.get("description", "") if isinstance(r, dict) else "",
                    url=r.get("url", target) if isinstance(r, dict) else target,
                    payload=r.get("payload") if isinstance(r, dict) else None,
                    evidence=r.get("evidence") if isinstance(r, dict) else None,
                )
                findings.append(f)
            logger.info("%s finished (%d findings)", pname, len(raw or []))
        except Exception as e:
            logger.exception("plugin %s failed (continuing): %s", pname, e)

    # --- 4) 결과 정리 및 저장 ---
    finished_at = datetime.utcnow().isoformat() if hasattr(datetime, "utcnow") else None
    results = {
        "targets": [target],
        "started_at": started_at,
        "finished_at": finished_at,
        "findings": [asdict(f) for f in findings],
    }

    out_path = output or f"scan_results_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json"
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False)
        logger.info("Saved scan results to %s", out_path)
    except Exception as e:
        logger.exception("Failed to save results file: %s", e)

    # 요약 출력
    click.echo("\n=== Scan Summary ===")
    click.echo(f"Target: {target}")
    click.echo(f"Total findings: {len(findings)}")
    by_plugin = {}
    for f in findings:
        by_plugin[f.plugin] = by_plugin.get(f.plugin, 0) + 1
    for k, v in by_plugin.items():
        click.echo(f" - {k}: {v}")
    click.echo("====================\n")

    # 종료 코드: findings 있으면 1, 없으면 0
    if findings:
        logger.warning("Findings detected: exiting with code 1")
        raise SystemExit(1)
    logger.info("No findings: exiting with code 0")
    raise SystemExit(0)
    
if __name__ == "__main__":
    cli()