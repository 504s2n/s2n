# S2N Scanner - Data Type Definition Document (EN)

## Table of Contents

1. [Overview](#overview)
2. [Type Hierarchy &amp; Data Flow](#type-hierarchy)
3. [Input Types](#input-types)
4. [Configuration Types](#configuration-types)
5. [Execution Types](#execution-types)
6. [Result Types](#result-types)
7. [Error Types](#error-types)
8. [Output Types](#output-types)

---

## Overview

### Purpose

Defines the common types used across all data flows of the `S2N Scanner`.

- The same types are used for CLI usage and Python import usage
- Clarify types for each stage (Input → Configuration → Execution → Result → Output)
- Ensure type safety and data consistency

### Design Principles

1. Immutability: Use immutable objects whenever possible
2. Serializable: Support JSON/YAML conversion
3. Type hints: Explicit type definitions for all fields
4. Documentation: Describe purpose and constraints of each field
5. Extensibility: Easy to add new plugins/features

---

## Type Hierarchy

```bash
Entry Point (CLI/Package)
    ↓
Input Types (ScanRequest, CLIArguments)
    ↓
Configuration Types (ScanConfig, PluginConfig, AuthConfig)
    ↓
Execution Types (ScanContext, PluginContext)
    ↓
Result Types (Finding, PluginResult, ScanReport)
    ↓
Output Types (JSONOutput, HTMLOutput, ConsoleOutput)
```

### Data Flow Summary

1. Input stage: `CLIArguments` → `ScanRequest`
2. Configuration stage: `ScanRequest` + Config Files → `ScanConfig`
3. Execution stage: `ScanConfig` → `ScanContext` → `PluginContext`
4. Result stage: `PluginContext` → `Finding` → `PluginResult` → `ScanReport`
5. Output stage: `ScanReport` → `JSONOutput` / `HTMLOutput` / `ConsoleOutput`

---

## Input Types

### 1. `ScanRequest`

- Purpose: Top-level data structure for a scan request
- Usage timing: After parsing CLI arguments or when calling the Python API

| Field             | Type                   | Required | Default   | Description                   |
| ----------------- | ---------------------- | -------- | --------- | ----------------------------- |
| `target_url`    | `str`                | ✅       | -         | URL to scan                   |
| `plugins`       | `List[str]`          | ❌       | `[]`    | List of plugins to use        |
| `config_path`   | `Optional[Path]`     | ❌       | `None`  | Path to configuration file    |
| `auth_type`     | `Optional[AuthType]` | ❌       | `None`  | Authentication type           |
| `output_format` | `OutputFormat`       | ❌       | `JSON`  | Output format                 |
| `output_path`   | `Optional[Path]`     | ❌       | `None`  | Output file path              |
| `verbose`       | `bool`               | ❌       | `False` | Whether to print verbose logs |

### 2. `CLIArguments`

- Purpose: Structure CLI command arguments
- Usage timing: Immediately after CLI argument parsing

Fields:

| Field             | Type                   | Required | Description                   |
| ----------------- | ---------------------- | -------- | ----------------------------- |
| `url` | `str` | ✅ | `--url`, `-u` |
| `plugin` | `List[str]` | ❌ | `--plugin`, `-p` (multiple allowed) |
| `config` | `Optional[str]` | ❌ | `--config`, `-c` |
| `auth` | `Optional[str]` | ❌ | `--auth`, `-a`|
| `username` | `Optional[str]` | ❌ | `--username` |
| `password` | `Optional[str]` | ❌ | `--password` |
| `output` | `Optional[str]` | ❌ | `--output`, `-o` |
| `depth` | `int` | ❌ | `--depth`, `-d` (default: `2`) |
| `verbose` | `bool` | ❌ | `--verbose`, `-v` |
| `log_file` | `Optional[str]` | ❌ | `--log-file` |

---

## Configuration Types

### 3. `ScanConfig`

- Purpose: Manage the overall scan configuration
- Usage timing: After `ScanRequest` is created, before scan execution

| Field             | Type                      | Default | Description                   |
| ----------------- | ------------------------- | ------- | ----------------------------- |
| `target_url`      | `str`                     | -       | URL to scan                   |
| `scanner_config`  | `ScannerConfig`           | -       | Scanner engine settings       |
| `plugin_configs`  | `Dict[str, PluginConfig]` | `{}`    | Per-plugin configurations     |
| `auth_config`     | `Optional[AuthConfig]`    | `None`  | Authentication settings        |
| `network_config`  | `NetworkConfig`           | -       | Network settings              |
| `output_config`   | `OutputConfig`            | -       | Output settings               |
| `logging_config`  | `LoggingConfig`           | -       | Logging settings              |

Creation methods:

- CLI arguments + defaults
- Load from YAML file
- Directly via Python API

---

### 4. `ScannerConfig`

- Purpose: Scanner engine runtime settings
- Usage timing: Part of `ScanConfig`

| Field             | Type   | Default                | Range      | Description                   |
| ----------------- | ------ | ---------------------- | ---------- | ----------------------------- |
| `crawl_depth`     | `int`  | `2`                    | 1-10       | Crawl depth                   |
| `max_threads`     | `int`  | `5`                    | 1-20       | Maximum threads               |
| `timeout`         | `int`  | `30`                   | 1-300      | Request timeout (seconds)     |
| `max_retries`     | `int`  | `3`                    | 0-10       | Maximum retry attempts        |
| `retry_delay`     | `float`| `1.0`                  | 0.1-10.0   | Retry delay (seconds)         |
| `user_agent`      | `str`  | `"S2N-Scanner/0.1.0"`   | -          | User-Agent header             |
| `follow_redirects`| `bool` | `True`                 | -          | Follow redirects              |
| `verify_ssl`      | `bool` | `True`                 | -          | Verify SSL certificates       |

---

### 5. `PluginConfig`

- Purpose: Configuration for an individual plugin
- Usage timing: Part of `ScanConfig.plugin_configs`

| Field               | Type                | Default | Description                        |
| ------------------- | ------------------- | ------- | ---------------------------------- |
| `enabled`           | `bool`              | `True`  | Whether the plugin is enabled      |
| `timeout`           | `int`               | `30`    | Plugin timeout                     |
| `max_payloads`      | `Optional[int]`     | `None`  | Maximum number of payloads         |
| `payload_file`      | `Optional[Path]`    | `None`  | Custom payload file                |
| `severity_threshold`| `Severity`          | `LOW`   | Minimum severity to report         |
| `skip_patterns`     | `List[str]`         | `[]`    | URL patterns to skip               |
| `custom_params`     | `Dict[str, Any]`    | `{}`    | Plugin-specific custom parameters  |

Example (SQL Injection plugin):

```python
PluginConfig(
    enabled=True,
    timeout=10,
    max_payloads=50,
    custom_params={
        'error_patterns': ['mysql_fetch', 'ORA-'],
        'blind_sleep_time': 5
    }
)
```

---

### 6. `AuthConfig`

- Purpose: Authentication settings
- Usage timing: Part of `ScanConfig`

| Field       | Type                | Required | Default | Description            |
| ----------- | ------------------- | -------- | ------- | ---------------------- |
| `auth_type` | `AuthType`          | ✅       | -       | Authentication type    |
| `username`  | `Optional[str]`     | ❌       | `None`  | Username               |
| `password`  | `Optional[str]`     | ❌       | `None`  | Password               |
| `token`     | `Optional[str]`     | ❌       | `None`  | Bearer token           |
| `api_key`   | `Optional[str]`     | ❌       | `None`  | API key                |
| `headers`   | `Dict[str, str]`    | ❌       | `{}`    | Custom headers         |
| `cookies`   | `Dict[str, str]`    | ❌       | `{}`    | Cookies                |

AuthType Enum:

- NONE: No authentication
- BASIC: HTTP Basic Auth
- BEARER: Bearer Token
- API_KEY: API Key
- COOKIE: Cookie-based
- CUSTOM: Custom headers

---

### 7. `NetworkConfig`

- Purpose: Network layer settings
- Usage timing: Part of `ScanConfig`

| Field              | Type             | Default | Description                        |
| ------------------ | ---------------- | ------- | ---------------------------------- |
| `max_connections`  | `int`            | `100`   | Maximum concurrent connections     |
| `connection_timeout`| `int`            | `10`    | Connection timeout (seconds)      |
| `read_timeout`     | `int`            | `30`    | Read timeout (seconds)             |
| `rate_limit`       | `Optional[float]`| `None`  | Maximum requests per second        |
| `proxy`            | `Optional[str]`  | `None`  | Proxy URL                          |
| `dns_cache_ttl`    | `int`            | `300`   | DNS cache TTL (seconds)            |

---

### 8. `OutputConfig`

- Purpose: Output settings
- Usage timing: Part of `ScanConfig`

| Field              | Type             | Default   | Description                   |
| ------------------ | ---------------- | --------- | ----------------------------- |
| `format`           | `OutputFormat`   | `JSON`    | Output format                 |
| `path`             | `Optional[Path]`| `None`    | Output file path              |
| `pretty_print`     | `bool`           | `True`    | JSON pretty print             |
| `include_timestamps`| `bool`          | `True`    | Include timestamps            |
| `include_metadata` | `bool`           | `True`    | Include metadata              |
| `console_mode`     | `ConsoleMode`    | `SUMMARY` | Console output mode           |

OutputFormat Enum:

- JSON: JSON file
- HTML: HTML report
- CSV: CSV file
- CONSOLE: Console-only output
- MULTI: Multiple formats

ConsoleMode Enum:

- SILENT: No output
- SUMMARY: Summary only
- VERBOSE: Detailed output
- DEBUG: Include debug information

---

### 9. `LoggingConfig`

- Purpose: Logging settings
- Usage timing: Part of `ScanConfig`

| Field           | Type             | Default                                      | Description                        |
| --------------- | ---------------- | -------------------------------------------- | ---------------------------------- |
| `level`         | `LogLevel`       | `INFO`                                       | Log level                          |
| `file_path`     | `Optional[Path]`| `None`                                       | Log file path                      |
| `console_output`| `bool`           | `True`                                       | Whether to print logs to console   |
| `format`        | `str`            | `"%(asctime)s - %(levelname)s - %(message)s"`| Log format                         |
| `max_file_size` | `int`            | `10485760`                                   | Max file size (bytes)              |
| `backup_count`  | `int`            | `3`                                          | Number of backup files             |

LogLevel Enum:

- DEBUG
- INFO
- WARNING
- ERROR
- CRITICAL

---

## Execution Types

### 10. `ScanContext`

- Purpose: Shared context during scan execution
- Usage timing: Created at scan start, passed to plugins

| Field            | Type             | Description                   |
| ---------------- | ---------------- | ----------------------------- |
| `scan_id`        | `str`            | Unique scan ID (UUID)         |
| `start_time`     | `datetime`       | Scan start time               |
| `config`         | `ScanConfig`     | Scan configuration            |
| `http_client`    | `HTTPClient`     | HTTP client instance          |
| `crawler`        | `Crawler`        | Crawler instance              |
| `session_data`   | `Dict[str, Any]` | Session data                  |
| `discovered_urls`| `Set[str]`       | Discovered URLs               |
| `visited_urls`   | `Set[str]`       | Visited URLs                  |

---

### 11. `PluginContext`

- Purpose: Context provided when running a plugin
- Usage timing: Created for each plugin execution

| Field           | Type           | Description                   |
| --------------- | -------------- | ----------------------------- |
| `plugin_name`   | `str`          | Plugin name                   |
| `scan_context`  | `ScanContext`  | Global scan context           |
| `plugin_config` | `PluginConfig` | Plugin configuration          |
| `target_urls`   | `List[str]`    | URLs for the plugin to scan   |
| `logger`        | `Logger`       | Logger instance               |

---

## Result Types

### 12. `Finding`

- Purpose: Individual vulnerability information
- Usage timing: Created when a vulnerability is detected

| Field          | Type                    | Required | Default | Description                        |
| -------------- | ----------------------- | -------- | ------- | ---------------------------------- |
| `id`           | `str`                   | ✅       | -       | Unique ID (e.g. "sql-001")         |
| `plugin`       | `str`                   | ✅       | -       | Plugin name                        |
| `severity`     | `Severity`              | ✅       | -       | Severity                           |
| `title`        | `str`                   | ✅       | -       | Vulnerability title                |
| `description`  | `str`                   | ✅       | -       | Detailed description               |
| `url`          | `Optional[str]`         | ❌       | `None`  | URL where it was found             |
| `parameter`    | `Optional[str]`         | ❌       | `None`  | Vulnerable parameter name           |
| `method`       | `Optional[str]`         | ❌       | `None`  | HTTP method                        |
| `payload`      | `Optional[str]`         | ❌       | `None`  | Attack payload                     |
| `evidence`     | `Optional[str]`         | ❌       | `None`  | Evidence of vulnerability          |
| `request`      | `Optional[HTTPRequest]` | ❌       | `None`  | Request information                |
| `response`     | `Optional[HTTPResponse]`| ❌       | `None`  | Response information               |
| `remediation`  | `Optional[str]`         | ❌       | `None`  | Remediation guidance               |
| `references`   | `List[str]`             | ❌       | `[]`    | Reference links                    |
| `cwe_id`       | `Optional[str]`         | ❌       | `None`  | CWE ID                             |
| `cvss_score`   | `Optional[float]`       | ❌       | `None`  | CVSS score (0.0-10.0)              |
| `cvss_vector`  | `Optional[str]`         | ❌       | `None`  | CVSS vector                        |
| `confidence`   | `Confidence`            | ❌       | `MEDIUM`| Confidence level                   |
| `timestamp`    | `datetime`              | -        | -       | Discovery time (automatic)         |

### Severity Enum

- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `LOW`
- `INFO`

### Confidence Enum

- `CERTAIN`
- `FIRM`
- `TENTATIVE`

---

### 13. `HTTPRequest`

- Purpose: HTTP request information
- Usage timing: Part of `Finding`

| Field     | Type                | Description     |
| --------- | ------------------- | --------------- |
| `method`  | `str`               | HTTP method     |
| `url`     | `str`               | Request URL     |
| `headers` | `Dict[str, str]`    | Request headers |
| `body`    | `Optional[str]`     | Request body    |
| `cookies` | `Dict[str, str]`    | Cookies         |

---

### 14. `HTTPResponse`

- Purpose: HTTP response information
- Usage timing: Part of `Finding`

| Field        | Type             | Description                        |
| ------------ | ---------------- | ---------------------------------- |
| `status_code`| `int`            | Status code                        |
| `headers`    | `Dict[str, str]` | Response headers                   |
| `body`       | `str`            | Response body (max 10KB)           |
| `elapsed_ms` | `float`          | Response time (milliseconds)       |

---

### 15. `PluginResult`

- Purpose: Plugin execution result
- Usage timing: Created after each plugin execution

| Field             | Type                    | Description                   |
| ----------------- | ----------------------- | ----------------------------- |
| `plugin_name`     | `str`                   | Plugin name                   |
| `status`          | `PluginStatus`          | Execution status              |
| `findings`        | `List[Finding]`         | List of found vulnerabilities |
| `start_time`      | `datetime`              | Start time                    |
| `end_time`        | `datetime`              | End time                      |
| `duration_seconds`| `float`                | Duration (seconds)            |
| `urls_scanned`    | `int`                   | Number of URLs scanned        |
| `requests_sent`   | `int`                   | Number of requests sent       |
| `error`           | `Optional[PluginError]` | Error information             |
| `metadata`        | `Dict[str, Any]`        | Additional metadata           |

PluginStatus Enum:

- SUCCESS
- PARTIAL
- FAILED
- SKIPPED
- TIMEOUT

---

### 16. `ScanReport`

- Purpose: Full scan report
- Usage timing: Created at scan completion

| Field             | Type                | Description                   |
| ----------------- | ------------------- | ----------------------------- |
| `scan_id`         | `str`               | Unique scan ID                |
| `target_url`      | `str`               | Target URL                    |
| `scanner_version` | `str`               | Scanner version               |
| `start_time`      | `datetime`          | Start time                    |
| `end_time`        | `datetime`          | End time                      |
| `duration_seconds`| `float`             | Total duration                |
| `config`          | `ScanConfig`        | Used configuration            |
| `plugin_results`  | `List[PluginResult]`| List of plugin results        |
| `summary`         | `ScanSummary`       | Summary information           |
| `metadata`        | `ScanMetadata`      | Metadata                      |

---

### 17. `ScanSummary`

- Purpose: Summary of scan results
- Usage timing: Part of `ScanReport`

| Field                  | Type                  | Description                        |
| ---------------------- | --------------------- | ---------------------------------- |
| `total_vulnerabilities`| `int`                 | Total number of vulnerabilities    |
| `severity_counts`      | `Dict[Severity, int]` | Counts per severity                |
| `plugin_counts`        | `Dict[str, int]`      | Counts per plugin                  |
| `total_urls_scanned`   | `int`                 | Total scanned URLs                 |
| `total_requests`       | `int`                 | Total requests                     |
| `success_rate`         | `float`               | Success rate (%)                   |
| `has_critical`         | `bool`                | Whether any Critical issues exist   |
| `has_high`             | `bool`                | Whether any High issues exist      |

---

### 18. `ScanMetadata`

- Purpose: Scan metadata
- Usage timing: Part of `ScanReport`

| Field           | Type                  | Description                        |
| --------------- | --------------------- | ---------------------------------- |
| `hostname`      | `str`                 | Hostname where executed            |
| `username`      | `str`                 | Executing user                     |
| `python_version`| `str`                 | Python version                     |
| `os_info`       | `str`                 | OS information                     |
| `cli_args`      | `Optional[List[str]]` | CLI arguments (if run via CLI)     |
| `config_file`   | `Optional[str]`       | Path to configuration file         |

---

## Error Types

### 19. `S2NException`

- Purpose: Base class for all S2N exceptions
- Usage timing: Raised when errors occur during scan execution

| Field       | Type                | Description            |
| ----------- | ------------------- | ---------------------- |
| `message`   | `str`               | Error message          |
| `error_code`| `str`               | Error code             |
| `timestamp` | `datetime`          | Occurrence time        |
| `context`   | `Dict[str, Any]`    | Additional context     |

Subclasses:

- NetworkError: Network-related errors
- AuthenticationError: Authentication failures
- ConfigurationError: Configuration errors
- PluginError: Plugin errors
- CrawlerError: Crawler errors
- ValidationError: Input validation errors

---

### 20. `ErrorReport`

- Purpose: Error information report
- Usage timing: Created when errors are captured

| Field         | Type                | Description                   |
| ------------- | ------------------- | ----------------------------- |
| `error_type`  | `str`               | Error type                    |
| `message`     | `str`               | Error message                 |
| `traceback`   | `Optional[str]`     | Stack trace                   |
| `timestamp`   | `datetime`          | Occurrence time               |
| `context`     | `Dict[str, Any]`    | Error context                 |
| `recoverable` | `bool`              | Whether it is recoverable     |
| `retry_count` | `int`               | Retry count                   |

---

## Output Types

### 21. `JSONOutput`

Purpose: JSON output format

Structure:

```json
{
  "scan_id": "uuid",
  "target_url": "http://...",
  "scanner_version": "0.1.0",
  "start_time": "ISO8601",
  "end_time": "ISO8601",
  "duration_seconds": 123.45,
  "summary": { ... },
  "plugin_results": [ ... ],
  "metadata": { ... }
}
```

---

### 22. `ConsoleOutput`

- Purpose: Data for console output
- Usage timing: Created for console output generation

| Field           | Type                    | Description                   |
| --------------- | ----------------------- | ----------------------------- |
| `mode`          | `ConsoleMode`           | Output mode                   |
| `summary_lines` | `List[str]`            | Summary lines                 |
| `detail_lines`  | `List[str]`            | Detail lines                  |
| `progress_info` | `Optional[ProgressInfo]`| Progress information          |

---

### 23. `ProgressInfo`

- Purpose: Progress information
- Usage timing: Part of `ConsoleOutput`

| Field        | Type   | Description                   |
| ------------ | ------ | ----------------------------- |
| `current`    | `int`  | Current progress              |
| `total`      | `int`  | Total count                   |
| `percentage` | `float`| Progress percentage (%)       |
| `message`    | `str`  | Progress message              |

---

## Enum Types Summary

All Enum types

They are defined in s2n/s2nscanner/interfaces.py:

MAIN branch
DEV branch

---

## Usage Examples

All types in this document are implemented in `s2n/s2nscanner/interfaces.py`.

### CLI Usage

```bash
s2n scan \
  --url http://target.com \
  --plugin sql --plugin xss \
  --auth basic \
  --username admin \
  --password pass \
  --output results.json \
  --verbose
```

### Python Import Usage

```python
from s2n import Scanner, ScanConfig, PluginConfig, AuthConfig
from s2n.interfaces import Severity, AuthType

# Create configuration
config = ScanConfig(
    target_url="http://target.com",
    scanner_config=ScannerConfig(crawl_depth=3),
    plugin_configs={
        "sql": PluginConfig(
            enabled=True,
            max_payloads=50
        )
    },
    auth_config=AuthConfig(
        auth_type=AuthType.BASIC,
        username="admin",
        password="pass"
    )
)

# Run scan
scanner = Scanner(config)
report = scanner.scan()

# Process results
print(f"Found vulnerabilities: {report.summary.total_vulnerabilities}")
for result in report.plugin_results:
    for finding in result.findings:
        if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
            print(f"[{finding.severity}] {finding.title}")
```
