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
$dataDirectory = Join-Path $dataRoot "Data"
$backupRoot = Join-Path $dataRoot ("Updates\backup-" + (Get-Date -Format "yyyyMMdd-HHmmss-fff") + "-" + [guid]::NewGuid().ToString("N").Substring(0,6))
$statusPath = Join-Path $dataDirectory "update-status.json"
$logPath = Join-Path $dataDirectory "update-install.log"
New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null

# PowerShell is launched as a detached LocalSystem process by even the legacy
# 1.2.133 agent. Do not depend on the old agent supporting any new command.
$mutex = [System.Threading.Mutex]::new($false, "Global\CRECCOM-SmartConsole-ManagedUpdate")
$acquired = $false
$backupComplete = $false
$installationTouched = $false

function Write-UpdateLog([string]$message) {
    try {
        Add-Content -Path $logPath -Encoding UTF8 -Value ("{0:o}  {1}" -f (Get-Date), $message)
    } catch { }
}

function Write-UpdateStatus([string]$state, [string]$message) {
    try {
        $currentVersion = "unknown"
        $exe = Join-Path $agentTarget "UsbAudit.Agent.exe"
        if (Test-Path $exe) { $currentVersion = (Get-Item $exe).VersionInfo.ProductVersion }
        $status = @{
            lastCheckedAt = (Get-Date).ToString("o")
            currentVersion = $currentVersion
            latestVersion = $currentVersion
            state = $state
            message = $message
        } | ConvertTo-Json
        # Use an atomic replace so the service/UI never read half a JSON object.
        $temp = $statusPath + ".installing.tmp"
        $status | Set-Content -Path $temp -Encoding UTF8 -Force
        Move-Item -Path $temp -Destination $statusPath -Force
    } catch { Write-UpdateLog ("Could not write update status: " + $_.Exception.Message) }
}

function Stop-UpdateProcesses {
    # The previous script left UsbAudit.Identity running, locking the Identity
    # executable and making Copy-Item fail. Always stop it before copying.
    Get-Process -Name "SmartConsole","UsbAudit.Identity","UsbAudit" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        Write-UpdateLog ("Stopping service " + $ServiceName)
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(45))
    }
    Start-Sleep -Seconds 2
    if ((Get-Service -Name $ServiceName).Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        throw "The agent service did not stop; no installation files will be replaced."
    }
}

function Copy-Version([string]$source, [string]$target) {
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            Copy-Item -Path (Join-Path $source "*") -Destination $target -Recurse -Force -ErrorAction Stop
            return
        } catch {
            if ($attempt -eq 5) { throw }
            Write-UpdateLog ("Copy attempt $attempt failed: " + $_.Exception.Message)
            Start-Sleep -Seconds ($attempt * 2)
        }
    }
}

function Confirm-CopiedBinary([string]$source, [string]$target) {
    if (-not (Test-Path $source) -or -not (Test-Path $target)) {
        throw "A required updated executable is missing."
    }
    $expected = (Get-FileHash -Path $source -Algorithm SHA256).Hash
    $actual = (Get-FileHash -Path $target -Algorithm SHA256).Hash
    if ($expected -ne $actual) {
        throw ("Updated executable verification failed: " + (Split-Path -Leaf $target))
    }
}

function Start-ManagedService {
    & sc.exe config $ServiceName start= auto | Out-Null
    & sc.exe failure $ServiceName reset= 0 actions= restart/5000/restart/15000/restart/30000 | Out-Null
    & sc.exe failureflag $ServiceName 1 | Out-Null
    Start-Service -Name $ServiceName -ErrorAction Stop
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(45))
    Write-UpdateLog ("Service " + $ServiceName + " is running.")
}

try {
    try { $acquired = $mutex.WaitOne(0) }
    catch [System.Threading.AbandonedMutexException] {
        $acquired = $true
        Write-UpdateLog "Recovered an abandoned prior update lock."
    }
    if (-not $acquired) {
        Write-UpdateLog "Another managed installer already owns the update lock. No second install started."
        exit 0
    }
    Write-UpdateLog ("Starting verified in-place update. Staging=" + $StagingRoot)
    if (-not (Test-Path (Join-Path $agentSource "UsbAudit.Agent.exe")) -or
        -not (Test-Path (Join-Path $appSource "SmartConsole.exe")) -or
        -not (Test-Path (Join-Path $identitySource "UsbAudit.Identity.exe"))) {
        throw "Staged update is incomplete: Agent, App or Identity executable is missing."
    }

    Stop-UpdateProcesses

    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    if (Test-Path $agentTarget) { Copy-Item $agentTarget (Join-Path $backupRoot "Agent") -Recurse -Force -ErrorAction Stop }
    if (Test-Path $appTarget) { Copy-Item $appTarget (Join-Path $backupRoot "App") -Recurse -Force -ErrorAction Stop }
    if (Test-Path $identityTarget) { Copy-Item $identityTarget (Join-Path $backupRoot "Identity") -Recurse -Force -ErrorAction Stop }
    if (Test-Path $managementTarget) { Copy-Item $managementTarget (Join-Path $backupRoot "Management") -Recurse -Force -ErrorAction Stop }
    $backupComplete = $true
    Write-UpdateLog "Backup completed."

    $installationTouched = $true
    Copy-Version $agentSource $agentTarget
    Copy-Version $appSource $appTarget
    Copy-Version $identitySource $identityTarget
    New-Item -ItemType Directory -Path $managementTarget -Force | Out-Null
    foreach ($name in @("Uninstall-UsbAudit.ps1", "Apply-UsbAuditUpdate.ps1", "Install-Latest-UsbAudit.ps1")) {
        $candidate = Join-Path $StagingRoot $name
        if (Test-Path $candidate) { Copy-Item -Path $candidate -Destination (Join-Path $managementTarget $name) -Force -ErrorAction Stop }
    }

    Confirm-CopiedBinary (Join-Path $agentSource "UsbAudit.Agent.exe") (Join-Path $agentTarget "UsbAudit.Agent.exe")
    Confirm-CopiedBinary (Join-Path $appSource "SmartConsole.exe") (Join-Path $appTarget "SmartConsole.exe")
    Confirm-CopiedBinary (Join-Path $identitySource "UsbAudit.Identity.exe") (Join-Path $identityTarget "UsbAudit.Identity.exe")
    Write-UpdateLog "All three updated binaries passed SHA-256 copy verification."

    $identityExe = Join-Path $identityTarget "UsbAudit.Identity.exe"
    $runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    New-Item -Path $runKey -Force | Out-Null
    Set-ItemProperty -Path $runKey -Name "CRECCOM Smart Console Identity" -Value ('"' + $identityExe + '"') -Type String

    Start-ManagedService
    # LocalSystem runs in session 0: do not launch a hidden desktop app there.
    # The signed-in user can reopen the Smart Console shortcut normally.
    Write-UpdateStatus "Updated" "The verified CRECCOM release was installed and the background service restarted."
    Write-UpdateLog "Managed update completed successfully."
} catch {
    $failure = $_
    Write-UpdateLog ("Managed update FAILED: " + $failure.Exception.ToString())
    # Record the failure in the existing tamper-evident audit outbox. The running
    # 1.2.133 agent can upload it after rollback; no new heartbeat schema is required.
    try {
        $reporter = Join-Path $agentSource "UsbAudit.Agent.exe"
        if (Test-Path $reporter) {
            $reason = $failure.Exception.Message
            if ($reason.Length -gt 550) { $reason = $reason.Substring(0, 550) }
            & $reporter --record-update-failure $reason
            if ($LASTEXITCODE -ne 0) { Write-UpdateLog "Update failure audit reporter returned an error." }
        }
    } catch { Write-UpdateLog ("Update failure reporter error: " + $_.Exception.Message) }
    if ($backupComplete -and $installationTouched) {
        try {
            Write-UpdateLog "Restoring prior version from verified backup."
            Stop-UpdateProcesses
            foreach ($folder in @("Agent","App","Identity","Management")) {
                $restoreSource = Join-Path $backupRoot $folder
                $restoreTarget = Join-Path $InstallRoot $folder
                if (Test-Path $restoreSource) {
                    Remove-Item -Path $restoreTarget -Recurse -Force -ErrorAction SilentlyContinue
                    Copy-Version $restoreSource $restoreTarget
                }
            }
            Write-UpdateLog "Rollback copy completed."
        } catch { Write-UpdateLog ("Rollback error: " + $_.Exception.ToString()) }
    }
    try { Start-ManagedService } catch { Write-UpdateLog ("Could not restart agent after failure: " + $_.Exception.ToString()) }
    Write-UpdateStatus "Update failed" $failure.Exception.Message
    exit 1
} finally {
    if ($acquired) { try { [void]$mutex.ReleaseMutex() } catch { } }
    $mutex.Dispose()
}
