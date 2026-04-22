@echo off
REM Build and run the link-preview reproducer in the same Ubuntu 24.04 +
REM Qt 6.4 environment as the production mumble-server.  Uses the default
REM Docker bridge network so we see whatever IPv4/IPv6 connectivity the
REM real server container has.

setlocal
set SCRIPT_DIR=%~dp0

echo === Building link-preview reproducer image ===
docker build -t link-preview-repro:latest "%SCRIPT_DIR%."
if %ERRORLEVEL% NEQ 0 (
	echo Build failed!
	exit /b 1
)

echo.
echo === Running reproducer (default bridge, dual-stack if available) ===
docker run --rm link-preview-repro:latest
