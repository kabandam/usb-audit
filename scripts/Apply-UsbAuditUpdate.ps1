param(
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$StagingRoot,
    [string]$ServiceName = "UsbAuditAgent"
)

$ErrorActionPreference = "Stop"
$agentTarget = Join-Path $InstallRoot "Agent"
$appTarget = Join-Path $InstallRoot "App"
$managementTarget = Join-Path $InstallRoot "Management"
$agentSource = Join-Path $StagingRoot "Agent"
$appSource = Join-Path $StagingRoot "App"
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

    if (-not (Test-Path $agentSource) -or -not (Test-Path $appSource)) {
        throw "Staged update is incomplete. Agent or App folder is missing."
    }

    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    if (Test-Path $agentTarget) { Copy-Item $agentTarget (Join-Path $backupRoot "Agent") -Recurse -Force }
    if (Test-Path $appTarget) { Copy-Item $appTarget (Join-Path $backupRoot "App") -Recurse -Force }
    if (Test-Path $managementTarget) { Copy-Item $managementTarget (Join-Path $backupRoot "Management") -Recurse -Force }

    New-Item -ItemType Directory -Path $agentTarget -Force | Out-Null
    New-Item -ItemType Directory -Path $appTarget -Force | Out-Null
    Copy-Item (Join-Path $agentSource "*") $agentTarget -Recurse -Force
    Copy-Item (Join-Path $appSource "*") $appTarget -Recurse -Force

    New-Item -ItemType Directory -Path $managementTarget -Force | Out-Null
    foreach ($scriptName in @("Uninstall-UsbAudit.ps1", "Apply-UsbAuditUpdate.ps1", "Install-Latest-UsbAudit.ps1")) {
        $candidate = Join-Path $StagingRoot $scriptName
        if (Test-Path $candidate) { Copy-Item $candidate (Join-Path $managementTarget $scriptName) -Force }
    }

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
        if (Test-Path (Join-Path $backupRoot "Management")) {
            Remove-Item $managementTarget -Recurse -Force -ErrorAction SilentlyContinue
            Copy-Item (Join-Path $backupRoot "Management") $managementTarget -Recurse -Force
        }
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    } catch { }
    Write-UpdateStatus "Update failed" $_.Exception.Message
    exit 1
}
