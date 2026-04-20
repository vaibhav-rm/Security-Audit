@echo off
REM ═══════════════════════════════════════════════════════════════
REM  pull-tools.bat  —  Download all Docker images for PRAWL
REM  Run this ONCE before using advanced scans.
REM  Requires: Docker Desktop running on Windows
REM ═══════════════════════════════════════════════════════════════

echo.
echo  PRAWL — Pulling vulnerability tool Docker images
echo  ═══════════════════════════════════════════════════
echo.

REM Check Docker is running
docker info > nul 2>&1
if %errorlevel% neq 0 (
    echo  ERROR: Docker Desktop is not running.
    echo  Please start Docker Desktop and try again.
    pause
    exit /b 1
)

echo  [1/3] Pulling Nmap ...
docker pull instrumentisto/nmap
if %errorlevel% neq 0 ( echo  WARNING: Nmap pull failed. ) else ( echo  ✓ Nmap ready. )

echo.
echo  [2/3] Pulling Nikto ...
docker pull frapsoft/nikto
if %errorlevel% neq 0 ( echo  WARNING: Nikto pull failed. ) else ( echo  ✓ Nikto ready. )

echo.
echo  [3/3] Pulling SQLMap ...
docker pull paoloo/sqlmap
if %errorlevel% neq 0 ( echo  WARNING: SQLMap pull failed. ) else ( echo  ✓ SQLMap ready. )

echo.
echo  ─────────────────────────────────────────────────────
echo  All images downloaded. You can now use Advanced Scans.
echo  ─────────────────────────────────────────────────────
echo.
pause
