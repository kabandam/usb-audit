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
$identitySource = Join-Path $scriptRoot "Identity"

if ($FromSource -or -not (Test-Path $agentSource) -or -not (Test-Path $appSource) -or -not (Test-Path $identitySource)) {
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw ".NET 8 SDK is required when installing directly from source."
    }
    $branding = Join-Path $root "scripts\Prepare-Branding.ps1"
    if (Test-Path $branding) { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $branding }
    $temp = Join-Path $env:TEMP "UsbAuditInstallBuild"
    if (Test-Path $temp) { Remove-Item $temp -Recurse -Force }
    New-Item -ItemType Directory -Path $temp | Out-Null
    $agentSource = Join-Path $temp "Agent"
    $appSource = Join-Path $temp "App"
    $identitySource = Join-Path $temp "Identity"
    & dotnet publish (Join-Path $root "src\UsbAudit.Agent\UsbAudit.Agent.csproj") -c Release -r win-x64 --self-contained true -o $agentSource
    if ($LASTEXITCODE -ne 0) { throw "Agent build failed." }
    & dotnet publish (Join-Path $root "src\UsbAudit.App\UsbAudit.App.csproj") -c Release -r win-x64 --self-contained true -o $appSource
    if ($LASTEXITCODE -ne 0) { throw "Desktop app build failed." }
    & dotnet publish (Join-Path $root "src\UsbAudit.Identity\UsbAudit.Identity.csproj") -c Release -r win-x64 --self-contained true -o $identitySource
    if ($LASTEXITCODE -ne 0) { throw "Microsoft 365 identity helper build failed." }
}

$installRoot = Join-Path $env:ProgramFiles "UsbAudit"
$agentTarget = Join-Path $installRoot "Agent"
$appTarget = Join-Path $installRoot "App"
$identityTarget = Join-Path $installRoot "Identity"
$managementTarget = Join-Path $installRoot "Management"
$dataRoot = Join-Path $env:ProgramData "UsbAudit"

Write-Host "Installing CRECCOM Smart Console..." -ForegroundColor Cyan

if (Get-Service -Name "UsbAuditAgent" -ErrorAction SilentlyContinue) {
    Stop-Service "UsbAuditAgent" -Force -ErrorAction SilentlyContinue
    & sc.exe delete "UsbAuditAgent" | Out-Null
    Start-Sleep -Seconds 1
}

New-Item -ItemType Directory -Path $agentTarget -Force | Out-Null
New-Item -ItemType Directory -Path $appTarget -Force | Out-Null
New-Item -ItemType Directory -Path $identityTarget -Force | Out-Null
New-Item -ItemType Directory -Path $managementTarget -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $dataRoot "Data") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $dataRoot "Archive") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $dataRoot "Updates") -Force | Out-Null

Copy-Item (Join-Path $agentSource "*") $agentTarget -Recurse -Force
Copy-Item (Join-Path $appSource "*") $appTarget -Recurse -Force
Copy-Item (Join-Path $identitySource "*") $identityTarget -Recurse -Force

foreach ($scriptName in @("Uninstall-UsbAudit.ps1", "Apply-UsbAuditUpdate.ps1", "Install-Latest-UsbAudit.ps1")) {
    $candidate = Join-Path $scriptRoot $scriptName
    if (Test-Path $candidate) {
        Copy-Item $candidate (Join-Path $managementTarget $scriptName) -Force
    }
}

# Audit data is restricted to Administrators and LocalSystem.
& icacls.exe $dataRoot /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

$agentExe = Join-Path $agentTarget "UsbAudit.Agent.exe"
New-Service -Name "UsbAuditAgent" -BinaryPathName "`"$agentExe`"" -DisplayName "Smart Console Agent" -StartupType Automatic | Out-Null
& sc.exe description "UsbAuditAgent" "CRECCOM Smart Console managed endpoint service for USB auditing and endpoint policy enforcement." | Out-Null

# Run continuously in the background. Windows starts it automatically after boot and
# restarts it after unexpected failures. Standard users cannot stop a LocalSystem
# service; an authorized administrator can still intentionally stop/uninstall it.
& sc.exe config "UsbAuditAgent" start= delayed-auto | Out-Null
& sc.exe failure "UsbAuditAgent" reset= 0 actions= restart/5000/restart/15000/restart/30000 | Out-Null
& sc.exe failureflag "UsbAuditAgent" 1 | Out-Null
Start-Service "UsbAuditAgent"

# Run the WAM identity helper in each interactive user's normal session at logon.
# The helper has no visible window and exits after CRECCOM Microsoft 365 enrollment succeeds.
$identityExe = Join-Path $identityTarget "UsbAudit.Identity.exe"
$runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
New-Item -Path $runKey -Force | Out-Null
Set-ItemProperty -Path $runKey -Name "CRECCOM Smart Console Identity" -Value ('"' + $identityExe + '"') -Type String

$appExe = Join-Path $appTarget "SmartConsole.exe"
$ws = New-Object -ComObject WScript.Shell

Remove-Item (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\USB Audit.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "USB Audit.lnk") -Force -ErrorAction SilentlyContinue

$startMenuShortcut = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Smart Console.lnk"
$shortcut = $ws.CreateShortcut($startMenuShortcut)
$shortcut.TargetPath = $appExe
$shortcut.WorkingDirectory = $appTarget
$shortcut.Description = "CRECCOM Smart Console"
$shortcut.Save()

$desktopShortcut = Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "Smart Console.lnk"
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
    Set-ItemProperty -Path $uninstallKey -Name DisplayName -Value "Smart Console"
    Set-ItemProperty -Path $uninstallKey -Name DisplayVersion -Value $version
    Set-ItemProperty -Path $uninstallKey -Name Publisher -Value "CRECCOM"
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

Write-Host "Smart Console installed." -ForegroundColor Green
Write-Host "Service: Smart Console Agent (running automatically)"
Write-Host "Console: Start menu or desktop > Smart Console"
Write-Host "Data: $dataRoot"
