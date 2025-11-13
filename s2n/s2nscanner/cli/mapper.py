from pathlib import Path
from s2n.s2nscanner.interfaces import CLIArguments, ScanRequest, AuthType, OutputFormat
from s2n.s2nscanner.interfaces import ValidationError

def cliargs_to_scanrequest(args: CLIArguments) -> ScanRequest:
    """
    CLIArguments -> ScanRequest 변환 함수
    CLI 입력값을 표준화된 ScanRequest 구조로 매핑
    """
    # URL 유효성 검증
    if not args.url or not args.url.startswith(("http://", "https://")):
        raise ValidationError(f"Invalid URL format: {args.url}")
    
    # AuthType 매핑
    auth_type = None
    if args.auth:
        upper_auth = args.auth.upper()
        if upper_auth == "DVWA":
            auth_type = AuthType.CUSTOM
        else:
            try:
                auth_type = AuthType(upper_auth)
            except ValueError:
                raise ValidationError(f"Unknown auth type: {args.auth}")
        
    # 변환 수행
    return ScanRequest(
        target_url=args.url,
        plugins=args.plugin or [],
        config_path=Path(args.config) if args.config else None,
        auth_type=auth_type,
        output_format=OutputFormat.JSON,
        output_path=Path(args.output) if args.output else None,
        verbose=args.verbose,
    )
