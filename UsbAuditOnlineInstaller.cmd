@echo off
setlocal
set "USB_AUDIT_INSTALLER=%~f0"
title USB Audit Online Installer
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$f=$env:USB_AUDIT_INSTALLER;$s=[IO.File]::ReadAllText($f);$m='# POWERSHELL_START';$i=$s.IndexOf($m);if($i -lt 0){throw 'Installer payload marker not found.'};iex $s.Substring($i+$m.Length)"
exit /b %errorlevel%
# POWERSHELL_START

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Repository = 'kabandam/usb-audit'

function Is-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Pause-Installer {
    Write-Host ''
    [void](Read-Host 'Press Enter to close')
}

try {
    if (-not (Is-Administrator)) {
        Write-Host 'Administrator permission is required. Windows will ask for approval.' -ForegroundColor Yellow
        $quoted = '"' + $env:USB_AUDIT_INSTALLER + '"'
        Start-Process -FilePath $env:ComSpec -ArgumentList "/c $quoted" -Verb RunAs | Out-Null
        exit 0
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $headers = @{
        Accept = 'application/vnd.github+json'
        'User-Agent' = 'UsbAudit-OnlineInstaller/1.2'
        'X-GitHub-Api-Version' = '2022-11-28'
    }

    Write-Host ''
    Write-Host 'USB Audit Online Installer' -ForegroundColor Cyan
    Write-Host 'Checking GitHub for the latest stable release...'

    try {
        $release = Invoke-RestMethod -UseBasicParsing -Headers $headers -Uri "https://api.github.com/repos/$Repository/releases/latest"
    }
    catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode.value__ -eq 404) {
            throw "No public USB Audit release was found at $Repository. Publish the first release and run this installer again."
        }
        throw
    }

    $zipName = 'UsbAudit-win-x64.zip'
    $zipAsset = $release.assets | Where-Object name -eq $zipName | Select-Object -First 1
    $sumAsset = $release.assets | Where-Object name -eq "$zipName.sha256" | Select-Object -First 1
    if (-not $zipAsset) { throw "Release $($release.tag_name) is missing $zipName." }
    if (-not $sumAsset) { throw "Release $($release.tag_name) is missing $zipName.sha256." }

    $work = Join-Path $env:TEMP ('UsbAuditInstall-' + [guid]::NewGuid().ToString('N'))
    $zip = Join-Path $work $zipName
    $sum = Join-Path $work "$zipName.sha256"
    $payload = Join-Path $work 'payload'
    New-Item -ItemType Directory -Path $work -Force | Out-Null

    try {
        Write-Host "Latest version: $($release.tag_name)"
        Write-Host 'Downloading package and checksum...'
        Invoke-WebRequest -UseBasicParsing -Uri $zipAsset.browser_download_url -OutFile $zip
        Invoke-WebRequest -UseBasicParsing -Uri $sumAsset.browser_download_url -OutFile $sum

        $text = Get-Content -Raw $sum
        if ($text -notmatch '(?i)\b([0-9a-f]{64})\b') { throw 'Published checksum is invalid.' }
        $expected = $Matches[1].ToUpperInvariant()
        $actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToUpperInvariant()
        if ($actual -ne $expected) { throw 'SHA-256 verification failed. Nothing was installed.' }
        Write-Host 'Package integrity verified.' -ForegroundColor Green

        Expand-Archive -Path $zip -DestinationPath $payload -Force
        $install = Join-Path $payload 'Install-UsbAudit.ps1'
        if (-not (Test-Path $install)) { throw 'The release package is missing Install-UsbAudit.ps1.' }

        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $install
        if ($LASTEXITCODE -ne 0) { throw "Installer returned exit code $LASTEXITCODE." }

        Write-Host ''
        Write-Host 'USB Audit installed successfully.' -ForegroundColor Green
        Write-Host 'The background service is running and future stable releases will update automatically.'
    }
    finally {
        Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch {
    Write-Host ''
    Write-Host "Installation failed: $($_.Exception.Message)" -ForegroundColor Red
    Pause-Installer
    exit 1
}

Pause-Installer
exit 0
