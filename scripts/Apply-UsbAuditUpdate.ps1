param(
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$StagingRoot,
    [string]$ServiceName = "UsbAuditAgent"
)

$ErrorActionPreference = "Stop"
$agentTarget = Join-Path $InstallRoot "Agent"
$appTarget = Join-Path $InstallRoot "App"
$identityTarget = Join-Path $InstallRoot "Identity"
$managementTarget = Join-Path $InstallRoot "Management"
$agentSource = Join-Path $StagingRoot "Agent"
$appSource = Join-Path $StagingRoot "App"
$identitySource = Join-Path $StagingRoot "Identity"
$dataRoot = Join-Path $env:ProgramData "UsbAudit"
$backupRoot = Join-Path $dataRoot ("Updates\backup-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
$statusPath = Join-Path $dataRoot "Data\update-status.json"

function Write-UpdateStatus([string]$state, [string]$message) {
    try {
        $currentVersion = "unknown"
        $exe = Join-Path $appTarget "UsbAudit.exe"
        if (Test-Path $exe) { $currentVersion = (Get-Item $exe).VersionInfo.ProductVersion }
        $status = @{
            lastCheckedAt = (Get-Date).ToString("o")
            currentVersion = $currentVersion
            latestVersion = $currentVersion
            state = $state
            message = $message
        } | ConvertTo-Json
        $status | Set-Content -Path $statusPath -Encoding UTF8
    } catch { }
}

try {
    $appWasRunning = @(Get-Process -Name "UsbAudit" -ErrorAction SilentlyContinue).Count -gt 0
    Get-Process -Name "UsbAudit" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    if (-not (Test-Path $agentSource) -or -not (Test-Path $appSource) -or -not (Test-Path $identitySource)) {
        throw "Staged update is incomplete. Agent, App, or Identity folder is missing."
    }

    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    if (Test-Path $agentTarget) { Copy-Item $agentTarget (Join-Path $backupRoot "Agent") -Recurse -Force }
    if (Test-Path $appTarget) { Copy-Item $appTarget (Join-Path $backupRoot "App") -Recurse -Force }
    if (Test-Path $identityTarget) { Copy-Item $identityTarget (Join-Path $backupRoot "Identity") -Recurse -Force }
    if (Test-Path $managementTarget) { Copy-Item $managementTarget (Join-Path $backupRoot "Management") -Recurse -Force }

    New-Item -ItemType Directory -Path $agentTarget -Force | Out-Null
    New-Item -ItemType Directory -Path $appTarget -Force | Out-Null
    New-Item -ItemType Directory -Path $identityTarget -Force | Out-Null
    Copy-Item (Join-Path $agentSource "*") $agentTarget -Recurse -Force
    Copy-Item (Join-Path $appSource "*") $appTarget -Recurse -Force
    Copy-Item (Join-Path $identitySource "*") $identityTarget -Recurse -Force

    New-Item -ItemType Directory -Path $managementTarget -Force | Out-Null
    foreach ($scriptName in @("Uninstall-UsbAudit.ps1", "Apply-UsbAuditUpdate.ps1", "Install-Latest-UsbAudit.ps1")) {
        $candidate = Join-Path $StagingRoot $scriptName
        if (Test-Path $candidate) { Copy-Item $candidate (Join-Path $managementTarget $scriptName) -Force }
    }

    & sc.exe config $ServiceName start= delayed-auto | Out-Null
    & sc.exe failure $ServiceName reset= 0 actions= restart/5000/restart/15000/restart/30000 | Out-Null
    & sc.exe failureflag $ServiceName 1 | Out-Null

    $identityExe = Join-Path $identityTarget "UsbAudit.Identity.exe"
    $runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    New-Item -Path $runKey -Force | Out-Null
    Set-ItemProperty -Path $runKey -Name "CRECCOM USB Audit Identity" -Value ('"' + $identityExe + '"') -Type String

    Start-Service -Name $ServiceName
    if ($appWasRunning) { Start-Process (Join-Path $appTarget "UsbAudit.exe") }
    Write-UpdateStatus "Updated" "USB Audit was updated successfully from GitHub Releases."
} catch {
    try {
        if (Test-Path (Join-Path $backupRoot "Agent")) {
            Remove-Item $agentTarget -Recurse -Force -ErrorAction SilentlyContinue
            Copy-Item (Join-Path $backupRoot "Agent") $agentTarget -Recurse -Force
        }
        if (Test-Path (Join-Path $backupRoot "App")) {
            Remove-Item $appTarget -Recurse -Force -ErrorAction SilentlyContinue
            Copy-Item (Join-Path $backupRoot "App") $appTarget -Recurse -Force
        }
        if (Test-Path (Join-Path $backupRoot "Identity")) {
            Remove-Item $identityTarget -Recurse -Force -ErrorAction SilentlyContinue
            Copy-Item (Join-Path $backupRoot "Identity") $identityTarget -Recurse -Force
        }
        if (Test-Path (Join-Path $backupRoot "Management")) {
            Remove-Item $managementTarget -Recurse -Force -ErrorAction SilentlyContinue
            Copy-Item (Join-Path $backupRoot "Management") $managementTarget -Recurse -Force
        }
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    } catch { }
    Write-UpdateStatus "Update failed" $_.Exception.Message
    exit 1
}
