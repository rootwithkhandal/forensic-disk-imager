# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Forgelens Disk Imager, please report it responsibly:

1. **Do NOT open a public GitHub issue** for security vulnerabilities.
2. **Email** your report to the repository maintainer with the subject line `[SECURITY] Forgelens Vulnerability Report`.
3. Include a detailed description of the vulnerability, steps to reproduce, and potential impact.
4. You can expect an initial acknowledgement within **72 hours** of your report.
5. We aim to provide a fix or mitigation within **14 days** for critical vulnerabilities.

## Scope

The following are in scope for security reports:

- Bypass of write-blocking mechanisms during forensic acquisition
- Unauthorized access to raw disk devices or physical memory
- Tampering with forensic hash integrity verification
- SQLite injection in case management or triage databases
- Arbitrary code execution via YARA rule loading
- Path traversal in file acquisition or report generation

## Out of Scope

- Vulnerabilities in third-party tools (e.g., WinPmem, avml, Volatility)
- Issues requiring physical access to the examiner's workstation
- Social engineering attacks
