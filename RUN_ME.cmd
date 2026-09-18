@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0itdiag.ps1" %*
echo.
echo Exit code: %ERRORLEVEL%
pause
