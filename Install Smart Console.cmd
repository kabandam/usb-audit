@echo off
setlocal
cd /d "%~dp0"
title CRECCOM Smart Console Installer

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Install-Latest-UsbAudit.ps1" -Interactive
exit /b %errorlevel%
