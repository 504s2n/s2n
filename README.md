# S2N — Plugin-based Web Vulnerability Scanner

<pre>
 (`-').->        <-. (`-')_
 ( OO)_             \( OO) )
(_)--\_)  .----. ,--./ ,--/
/    _ / \_,-.  ||   \ |  |
\_..`--.    .' .'|  . '|  |)
.-._)   \ .'  /_ |  |\    |
\       /|      ||  | \   |
 `-----' `------'`--'  `--'
</pre>

> A lightweight, plugin-driven web vulnerability scanner library.
> Core data types and interfaces are defined in `s2n.s2nscanner.interfaces`.
> More detailed type Documentation is available in [`interfaces.en.md`](/docs/interfaces.en.md).

---

## Quick install

### CLI usage

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

### Python usage

```python
from s2n import Scanner, ScanConfig, PluginConfig, AuthConfig
from s2n.interfaces import Severity, AuthType

# Create ScanConfig
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

# Execute Scan with ScanConfig parameter
scanner = Scanner(config)
report = scanner.scan()

# 결과 처리
print(f"[RESULT]: {report.summary.total_vulnerabilities}개")
for result in report.plugin_results:
    for finding in result.findings:
        if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
            print(f"[{finding.severity}] {finding.title}")

```

---

## Key type references

### Documentation

- Data type reference: `interfaces.en.md`
- Source: `interfaces.py`

### Core types and data models:

- `s2n.s2nscanner.interfaces.ScanConfig`
- `s2n.s2nscanner.interfaces.PluginConfig`
- `s2n.s2nscanner.interfaces.ScannerConfig`

### Results & reporting:

- `s2n.s2nscanner.interfaces.ScanReport`
- `s2n.s2nscanner.interfaces.Finding`

### Enums:

- `s2n.s2nscanner.interfaces.Severity`
- `s2n.s2nscanner.interfaces.PluginStatus`

## Features

Plugin architecture for modular vulnerability checks Structured data models for requests,
results and outputs Multiple output formats (`JSON`, `HTML`, `console`)
Configurable scanner behavior and per-plugin settings.

---

## LICENSE

---

## Contributing

Follow the project coding style and add tests for new features.  
Update type docs in interfaces.en.md when interfaces change.
