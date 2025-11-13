from typing import Optional

from s2n.s2nscanner.interfaces import (
    ScanRequest,
    ScanConfig,
    ScannerConfig,
    NetworkConfig,
    OutputConfig,
    LoggingConfig,
    AuthConfig,
    AuthType,
    PluginConfig,
)


def build_scan_config(
    req: ScanRequest,
    *,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> ScanConfig:
    """
    ScanRequest -> ScanConfig 변환
    CLI 입력 기반으로 실제 Scanner 실행 설정 구성
    """

    # 인증 설정 구성
    auth_config = None
    if req.auth_type and req.auth_type != AuthType.NONE:
        auth_config = AuthConfig(
            auth_type=req.auth_type,
            username=username,
            password=password,
        )
    
    # 출력 설정 구성
    output_cfg = OutputConfig(
        format=req.output_format,
        path=req.output_path,
        pretty_print=True,
        console_mode=("DEBUG" if req.verbose else "SUMMARY"),
    )

    # 로깅 설정 구성
    logging_cfg = LoggingConfig(
        level=("DEBUG" if req.verbose else "INFO"),
        console_output=True,
    )

    plugin_configs: dict[str, PluginConfig] = {}
    if req.plugins:
        for plugin_name in req.plugins:
            if plugin_name:
                plugin_configs[plugin_name.lower()] = PluginConfig()

    # 최종 구성 반환
    return ScanConfig(
        target_url=req.target_url,
        scanner_config=ScannerConfig(crawl_depth=2),
        plugin_configs=plugin_configs,
        auth_config=auth_config,
        network_config=NetworkConfig(),
        output_config=output_cfg,
        logging_config=logging_cfg,
    )
