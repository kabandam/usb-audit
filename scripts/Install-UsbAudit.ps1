param(
    [switch]$FromSource,
    [switch]$SkipUninstallRegistration
)

$ErrorActionPreference = "Stop"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator, then run this installer again."
    }
}

Assert-Administrator

$scriptRoot = $PSScriptRoot
$root = Split-Path -Parent $scriptRoot
$agentSource = Join-Path $scriptRoot "Agent"
$appSource = Join-Path $scriptRoot "App"

if ($FromSource -or -not (Test-Path $agentSource) -or -not (Test-Path $appSource)) {
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw ".NET 8 SDK is required when installing directly from source."
    }
    $temp = Join-Path $env:TEMP "UsbAuditInstallBuild"
    if (Test-Path $temp) { Remove-Item $temp -Recurse -Force }
    New-Item -ItemType Directory -Path $temp | Out-Null
    $agentSource = Join-Path $temp "Agent"
    $appSource = Join-Path $temp "App"
    & dotnet publish (Join-Path $root "src\UsbAudit.Agent\UsbAudit.Agent.csproj") -c Release -r win-x64 --self-contained true -o $agentSource
    if ($LASTEXITCODE -ne 0) { throw "Agent build failed." }
    & dotnet publish (Join-Path $root "src\UsbAudit.App\UsbAudit.App.csproj") -c Release -r win-x64 --self-contained true -o $appSource
    if ($LASTEXITCODE -ne 0) { throw "Desktop app build failed." }
}

$installRoot = Join-Path $env:ProgramFiles "UsbAudit"
$agentTarget = Join-Path $installRoot "Agent"
$appTarget = Join-Path $installRoot "App"
$managementTarget = Join-Path $installRoot "Management"
$dataRoot = Join-Path $env:ProgramData "UsbAudit"

Write-Host "Installing USB Audit..." -ForegroundColor Cyan

if (Get-Service -Name "UsbAuditAgent" -ErrorAction SilentlyContinue) {
    Stop-Service "UsbAuditAgent" -Force -ErrorAction SilentlyContinue
    & sc.exe delete "UsbAuditAgent" | Out-Null
    Start-Sleep -Seconds 1
}

New-Item -ItemType Directory -Path $agentTarget -Force | Out-Null
New-Item -ItemType Directory -Path $appTarget -Force | Out-Null
New-Item -ItemType Directory -Path $managementTarget -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $dataRoot "Data") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $dataRoot "Archive") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $dataRoot "Updates") -Force | Out-Null

Copy-Item (Join-Path $agentSource "*") $agentTarget -Recurse -Force
Copy-Item (Join-Path $appSource "*") $appTarget -Recurse -Force

foreach ($scriptName in @("Uninstall-UsbAudit.ps1", "Apply-UsbAuditUpdate.ps1", "Install-Latest-UsbAudit.ps1")) {
    $candidate = Join-Path $scriptRoot $scriptName
    if (Test-Path $candidate) {
        Copy-Item $candidate (Join-Path $managementTarget $scriptName) -Force
    }
}

# Audit data is restricted to Administrators and LocalSystem.
& icacls.exe $dataRoot /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

$agentExe = Join-Path $agentTarget "UsbAudit.Agent.exe"
New-Service -Name "UsbAuditAgent" -BinaryPathName "`"$agentExe`"" -DisplayName "USB Audit Agent" -StartupType Automatic | Out-Null
& sc.exe description "UsbAuditAgent" "Monitors removable USB storage and records administrator-visible audit evidence." | Out-Null
& sc.exe failure "UsbAuditAgent" reset= 86400 actions= restart/5000/restart/15000/restart/30000 | Out-Null
Start-Service "UsbAuditAgent"

$appExe = Join-Path $appTarget "UsbAudit.exe"
$ws = New-Object -ComObject WScript.Shell

$startMenuShortcut = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\USB Audit.lnk"
$shortcut = $ws.CreateShortcut($startMenuShortcut)
$shortcut.TargetPath = $appExe
$shortcut.WorkingDirectory = $appTarget
$shortcut.Description = "USB Audit administrator console"
$shortcut.Save()

$desktopShortcut = Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "USB Audit.lnk"
$shortcut = $ws.CreateShortcut($desktopShortcut)
$shortcut.TargetPath = $appExe
$shortcut.WorkingDirectory = $appTarget
$shortcut.Description = "USB Audit administrator console"
$shortcut.Save()

# Register a normal Apps & Features entry for script/online installs.
# Conventional Setup.exe builds let Inno Setup own the uninstall registry entry.
if (-not $SkipUninstallRegistration) {
    $version = (Get-Item $appExe).VersionInfo.ProductVersion
    if ([string]::IsNullOrWhiteSpace($version)) { $version = "1.0.0" }
    $uninstallScript = Join-Path $managementTarget "Uninstall-UsbAudit.ps1"
    $uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UsbAudit"
    New-Item -Path $uninstallKey -Force | Out-Null
    Set-ItemProperty -Path $uninstallKey -Name DisplayName -Value "USB Audit"
    Set-ItemProperty -Path $uninstallKey -Name DisplayVersion -Value $version
    Set-ItemProperty -Path $uninstallKey -Name Publisher -Value "USB Audit"
    Set-ItemProperty -Path $uninstallKey -Name InstallLocation -Value $installRoot
    Set-ItemProperty -Path $uninstallKey -Name DisplayIcon -Value $appExe
    if (Test-Path $uninstallScript) {
        $uninstallCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$uninstallScript`""
        Set-ItemProperty -Path $uninstallKey -Name UninstallString -Value $uninstallCommand
    }
    Set-ItemProperty -Path $uninstallKey -Name NoModify -Value 1 -Type DWord
    Set-ItemProperty -Path $uninstallKey -Name NoRepair -Value 1 -Type DWord
}

# Inter is intentionally not bundled. The app requests the system-installed Inter family and falls back through Windows font substitution.
$inter = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" -ErrorAction SilentlyContinue |
    Get-Member -MemberType NoteProperty | Where-Object Name -Match "Inter"
if (-not $inter) {
    Write-Warning "Inter font was not detected. Install Google Inter on this PC for the intended branded appearance."
}

Write-Host "USB Audit installed." -ForegroundColor Green
Write-Host "Service: USB Audit Agent (running automatically)"
Write-Host "Console: Start menu or desktop > USB Audit"
Write-Host "Data: $dataRoot"
