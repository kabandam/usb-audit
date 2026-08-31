param(
    [string]$Repository = "kabandam/usb-audit",
    [switch]$Interactive
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Wait-IfInteractive {
    if ($Interactive) {
        Write-Host ""
        [void](Read-Host "Press Enter to close")
    }
}

function Invoke-ElevatedSelf {
    $arguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"' + $PSCommandPath + '"'),
        "-Repository", ('"' + $Repository + '"')
    )
    if ($Interactive) { $arguments += "-Interactive" }

    Start-Process -FilePath "powershell.exe" -ArgumentList ($arguments -join " ") -Verb RunAs | Out-Null
}

function Get-Sha256Hex([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToUpperInvariant()
}

function Get-ExpectedHash($Release, [string]$ZipAssetName) {
    $zipAsset = $Release.assets | Where-Object { $_.name -eq $ZipAssetName } | Select-Object -First 1
    if ($null -ne $zipAsset -and $zipAsset.PSObject.Properties.Name -contains "digest") {
        $digest = [string]$zipAsset.digest
        if ($digest -match '^sha256:([0-9a-fA-F]{64})$') {
            return $Matches[1].ToUpperInvariant()
        }
    }

    $checksumAsset = $Release.assets | Where-Object { $_.name -eq "$ZipAssetName.sha256" } | Select-Object -First 1
    if ($null -eq $checksumAsset) {
        throw "The latest release does not contain $ZipAssetName.sha256, so the installer cannot verify the download."
    }

    $checksumPath = Join-Path $env:TEMP ("UsbAudit-" + [guid]::NewGuid().ToString("N") + ".sha256")
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $checksumAsset.browser_download_url -OutFile $checksumPath
        $checksumText = Get-Content -Raw -Path $checksumPath
        if ($checksumText -notmatch '(?i)\b([0-9a-f]{64})\b') {
            throw "The published checksum file is invalid."
        }
        return $Matches[1].ToUpperInvariant()
    }
    finally {
        Remove-Item $checksumPath -Force -ErrorAction SilentlyContinue
    }
}

try {
    if (-not (Test-Administrator)) {
        Write-Host "USB Audit needs administrator permission to install." -ForegroundColor Yellow
        Invoke-ElevatedSelf
        exit 0
    }

    if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
        throw "Repository must use owner/repository format."
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $headers = @{
        Accept = "application/vnd.github+json"
        "User-Agent" = "UsbAudit-OnlineInstaller/1.2"
        "X-GitHub-Api-Version" = "2022-11-28"
    }

    Write-Host "" 
    Write-Host "USB Audit Online Installer" -ForegroundColor Cyan
    Write-Host "Repository: $Repository"
    Write-Host "Checking GitHub for the latest stable release..."

    $releaseUri = "https://api.github.com/repos/$Repository/releases/latest"
    try {
        $release = Invoke-RestMethod -UseBasicParsing -Headers $headers -Uri $releaseUri
    }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 404) {
            throw "No public USB Audit release was found at $Repository. Create the repository and publish its first release, then run this installer again."
        }
        throw
    }

    $zipAssetName = "UsbAudit-win-x64.zip"
    $zipAsset = $release.assets | Where-Object { $_.name -eq $zipAssetName } | Select-Object -First 1
    if ($null -eq $zipAsset) {
        throw "Release $($release.tag_name) does not contain $zipAssetName."
    }

    $expectedHash = Get-ExpectedHash $release $zipAssetName
    $workRoot = Join-Path $env:TEMP ("UsbAuditInstall-" + [guid]::NewGuid().ToString("N"))
    $zipPath = Join-Path $workRoot $zipAssetName
    $extractPath = Join-Path $workRoot "payload"
    New-Item -ItemType Directory -Path $workRoot -Force | Out-Null

    try {
        Write-Host "Latest version: $($release.tag_name)"
        Write-Host "Downloading the verified Windows package..."
        Invoke-WebRequest -UseBasicParsing -Uri $zipAsset.browser_download_url -OutFile $zipPath

        $actualHash = Get-Sha256Hex $zipPath
        if ($actualHash -ne $expectedHash) {
            throw "SHA-256 verification failed. The package was not installed."
        }
        Write-Host "Package verified: SHA-256 OK" -ForegroundColor Green

        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
        $installer = Join-Path $extractPath "Install-UsbAudit.ps1"
        if (-not (Test-Path $installer)) {
            throw "The release package is missing Install-UsbAudit.ps1."
        }

        Write-Host "Installing USB Audit..."
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installer
        if ($LASTEXITCODE -ne 0) {
            throw "USB Audit installation returned exit code $LASTEXITCODE."
        }

        Write-Host ""
        Write-Host "USB Audit is installed and the background monitoring service is running." -ForegroundColor Green
        Write-Host "Future stable releases will be picked up automatically by the installed updater."
    }
    finally {
        Remove-Item $workRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch {
    Write-Host ""
    Write-Host "Installation failed: $($_.Exception.Message)" -ForegroundColor Red
    Wait-IfInteractive
    exit 1
}

Wait-IfInteractive
exit 0
