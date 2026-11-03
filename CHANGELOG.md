# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-03

### Added
- 16 read-only health checks: OS version, uptime, pending reboot, CPU, memory, top memory processes, startup programs, disk space per drive, Windows Update, antivirus (Defender and third-party), firewall profiles, BitLocker, failed logins, network adapters, internet connectivity, battery health.
- PASS / WARN / FAIL / INFO status with a reason and a recommendation for every check.
- Weighted health score out of 100 with a grade.
- Coloured console summary.
- Self-contained HTML report with light and dark themes.
- JSON export (`-Json`).
- Parameters: `-OutputPath`, `-NoHtml`, `-Quiet`, `-SkipUpdateCheck`, `-OpenReport`, `-PassThru`, `-DemoData`.
- Exit codes 0 / 1 / 2 for use in scripts and RMM tools.
- `Run-HealthCheck.cmd` double-click launcher.
- Pester test suite with mocked Windows cmdlets.
- GitHub Actions workflow for Windows PowerShell 5.1 and PowerShell 7.
