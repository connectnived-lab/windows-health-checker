@echo off
REM Windows Health Checker - double-click launcher.
REM Runs the read-only health check and opens the HTML report.
REM Any extra arguments are passed to the script, e.g. Run-HealthCheck.cmd -Json

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\WindowsHealthChecker.ps1" -OpenReport %*
echo.
pause
