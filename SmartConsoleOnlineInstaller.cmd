@echo off
setlocal EnableExtensions
title CRECCOM Smart Console Online Installer

set "BASE_URL=https://github.com/kabandam/usb-audit/releases/latest/download"
set "WORK=%TEMP%\SmartConsoleInstall-%RANDOM%%RANDOM%"
set "SETUP=%WORK%\SmartConsoleSetup.exe"
set "SUM=%WORK%\SmartConsoleSetup.exe.sha256"
set "SC_SETUP=%SETUP%"

echo.
echo CRECCOM Smart Console Online Installer
echo Downloading the latest approved installer...
mkdir "%WORK%" >nul 2>&1
if errorlevel 1 goto :fail

where curl.exe >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoLogo -NoProfile -NonInteractive -Command "Invoke-WebRequest -UseBasicParsing -Uri '%BASE_URL%/SmartConsoleSetup.exe' -OutFile $env:SC_SETUP"
  if errorlevel 1 goto :fail
  powershell.exe -NoLogo -NoProfile -NonInteractive -Command "Invoke-WebRequest -UseBasicParsing -Uri '%BASE_URL%/SmartConsoleSetup.exe.sha256' -OutFile '%SUM%'"
  if errorlevel 1 goto :fail
) else (
  curl.exe -fL --retry 3 --retry-delay 2 -o "%SETUP%" "%BASE_URL%/SmartConsoleSetup.exe"
  if errorlevel 1 goto :fail
  curl.exe -fL --retry 3 --retry-delay 2 -o "%SUM%" "%BASE_URL%/SmartConsoleSetup.exe.sha256"
  if errorlevel 1 goto :fail
)

for /f "tokens=1" %%H in ('type "%SUM%"') do set "EXPECTED=%%H"
for /f %%H in ('powershell.exe -NoLogo -NoProfile -NonInteractive -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath $env:SC_SETUP).Hash.ToLowerInvariant()"') do set "ACTUAL=%%H"

if not defined EXPECTED goto :hashfail
if not defined ACTUAL goto :hashfail
if /I not "%EXPECTED%"=="%ACTUAL%" goto :hashfail

echo Package integrity verified.
powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$s=Get-AuthenticodeSignature -LiteralPath $env:SC_SETUP; if($s.Status -eq 'Valid'){ Write-Host ('Publisher signature verified: ' + $s.SignerCertificate.Subject) -ForegroundColor Green } else { Write-Warning ('Publisher signature status: ' + $s.Status + '. SHA-256 integrity verification succeeded, but a CRECCOM code-signing certificate is not yet present on this release.') }"

echo Starting Smart Console Setup...
start "" /wait "%SETUP%"
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" goto :setupfail

echo.
echo Smart Console installation completed.
goto :cleanup

:hashfail
echo.
echo ERROR: SHA-256 verification failed. Nothing was installed.
set "RC=2"
goto :cleanup

:setupfail
echo.
echo ERROR: Smart Console Setup returned exit code %RC%.
goto :cleanup

:fail
echo.
echo ERROR: The installer could not be downloaded.
set "RC=1"

:cleanup
del /q "%SUM%" >nul 2>&1
del /q "%SETUP%" >nul 2>&1
rmdir "%WORK%" >nul 2>&1
echo.
pause
exit /b %RC%
