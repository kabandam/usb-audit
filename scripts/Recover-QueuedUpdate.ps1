#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Recover a Smart Console update that remains stuck at "Queued".
.DESCRIPTION
    Uses the EXISTING Windows Smart Console Agent service and its managed,
    checksum-verified update feed. It does not download or install untrusted
    code, reset the computer enrollment, or modify existing settings/data.
    Supports older Smart Console versions that honor the inventory force-
    install request flag (including 1.2.194).
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$dataRoot = Join-Path $env:ProgramData 'UsbAudit'
$dataDir = Join-Path $dataRoot 'Data'
$statusFile = Join-Path $dataDir 'update-status.json'
$forceFlag = Join-Path $dataDir 'inventory-update-request.flag'
$agentExe = Join-Path (Join-Path $env:ProgramFiles 'UsbAudit') 'Agent\UsbAudit.Agent.exe'

function Get-UpdateState {
    if (-not (Test-Path -LiteralPath $statusFile -PathType Leaf)) { return $null }
    try {
        return Get-Content -LiteralPath $statusFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch { return $null }
}

function Test-Installing {
    $status = Get-UpdateState
    if ($null -ne $status -and $status.state -match '^(Installing|Downloading|Repair installing|Repair downloading)$') {
        return $true
    }
    $pendingPath = Join-Path $dataDir 'PendingDeployments'
    if (Test-Path -LiteralPath $pendingPath) {
        foreach ($file in Get-ChildItem -LiteralPath $pendingPath -Filter '*.json' -File -ErrorAction SilentlyContinue) {
            try {
                $deployment = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
                if ($deployment.state -eq 'installing') { return $true }
            } catch { }
        }
    }
    return $false
}

try {
    Write-Host 'CRECCOM Smart Console | Queued Update Recovery' -ForegroundColor Cyan
    Write-Host 'This recovery will preserve terminal enrollment, settings, and audit records.'
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='UsbAuditAgent'" -ErrorAction Stop
    if ($null -eq $service) {
        throw 'The Windows agent service is missing. The queued request cannot run without the agent; use the approved Smart Console repair package.'
    }
    if (-not (Test-Path -LiteralPath $agentExe -PathType Leaf)) {
        throw 'The installed agent executable is missing. Use the approved Smart Console repair package to restore missing program files.'
    }
    # Fail closed if the service executable is unexpectedly outside the known
    # CRECCOM program directory; never restart an unrecognized service path.
    $actualBin = [string]$service.PathName
    if ($actualBin.Trim() -notmatch '^"?.*UsbAudit\.Agent\.exe"?(?:\s|$)' -or
        -not $actualBin.ToLowerInvariant().Contains($agentExe.ToLowerInvariant())) {
        throw "The installed service path does not match the expected CRECCOM agent. An administrator should review its configuration."
    }

    if (Test-Installing) {
        Write-Host 'An installation or deployment is already active. It was not interrupted.' -ForegroundColor Yellow
        exit 0
    }

    New-Item -ItemType Directory -Path $dataDir -Force -ErrorAction Stop | Out-Null
    $serviceState = Get-Service -Name 'UsbAuditAgent' -ErrorAction Stop
    if ($serviceState.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        Write-Host 'Starting the stopped Smart Console Agent...'
        Start-Service -Name 'UsbAuditAgent' -ErrorAction Stop
    } elseif ($serviceState.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
        $status = Get-UpdateState
        $oldQueued = $null -ne $status -and $status.state -eq 'Queued'
        if ($oldQueued -and $status.lastCheckedAt) {
            try { $oldQueued = ((Get-Date) - ([DateTimeOffset]::Parse([string]$status.lastCheckedAt)).LocalDateTime).TotalSeconds -gt 45 }
            catch { $oldQueued = $true }
        }
        if ($oldQueued) {
            Write-Host 'Update has not been acknowledged. Restarting the existing agent service...'
            Restart-Service -Name 'UsbAuditAgent' -ErrorAction Stop
        } else {
            Write-Host 'The agent is running; leaving it uninterrupted.'
        }
    } else {
        throw ('The agent service is ' + $serviceState.Status + '. Resolve the Windows service state before requesting an update.')
    }

    # 1.2.194 explicitly treats this flag as a forced managed installation.
    # It works even if automatic installation was turned off in older settings.
    Set-Content -LiteralPath $forceFlag -Value ([DateTimeOffset]::UtcNow.ToString('O')) -Encoding ascii -ErrorAction Stop
    Write-Host 'The existing agent has been instructed to install the latest verified release.' -ForegroundColor Green

    $changed = $false
    for ($attempt = 0; $attempt -lt 45; $attempt++) {
        Start-Sleep -Seconds 1
        $status = Get-UpdateState
        if ($status -and $status.state -notin @('Queued', 'Not checked')) {
            $changed = $true
            Write-Host ('Agent status: ' + $status.state)
            if ($status.message) { Write-Host ([string]$status.message) }
            break
        }
    }
    if (-not $changed) {
        Write-Warning 'The agent did not report an update acknowledgement. No endpoint settings or audit data were changed.'
        Write-Host 'Check the Smart Console Agent service and the Windows Event Viewer, or use the approved online repair package.'
        exit 2
    }
    if ($status.state -match 'failed|error') { exit 3 }
    Write-Host 'You can reopen Smart Console to watch the update status and confirm the installed version.'
    exit 0
} catch {
    Write-Error ('Queued update recovery could not finish: ' + $_.Exception.Message)
    exit 1
}
