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
# Keep rollback on the SAME VOLUME and parent as the installation. Renaming an
# existing directory is atomic and does not traverse legacy Identity/Identity
# nesting that previously caused the updater to fail on long paths.
$backupRoot = Join-Path $InstallRoot (".rollback-" + (Get-Date -Format "yyyyMMdd-HHmmss-fff") + "-" + [guid]::NewGuid().ToString("N").Substring(0,6))
$statusPath = Join-Path $dataDirectory "update-status.json"
$logPath = Join-Path $dataDirectory "update-install.log"
New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null

# PowerShell is launched as a detached LocalSystem process by even the legacy
# 1.2.133 agent. Do not depend on the old agent supporting any new command.
$mutex = [System.Threading.Mutex]::new($false, "Global\CRECCOM-SmartConsole-ManagedUpdate")
$acquired = $false
$backupStarted = $false
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

function Move-Version([string]$source, [string]$target) {
    if (-not (Test-Path -LiteralPath $source)) { return }
    if (Test-Path -LiteralPath $target) { throw "The rollback destination already exists: $target" }
    # Move-Item on the same volume is a root directory rename, not recursive copy.
    # This is essential for legacy endpoints where earlier failed rollbacks
    # accidentally produced 20+ nested Identity folders.
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        try {
            Move-Item -LiteralPath $source -Destination $target -ErrorAction Stop
            return
        } catch {
            if ($attempt -eq 4) { throw }
            Write-UpdateLog ("Directory move attempt $attempt failed: " + $_.Exception.Message)
            Start-Sleep -Seconds ($attempt * 2)
        }
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

    New-Item -ItemType Directory -Path $backupRoot -Force -ErrorAction Stop | Out-Null
    $backupStarted = $true
    # Moving directory roots preserves every existing file for rollback without
    # attempting to recursively copy an already-corrupted Identity tree.
    Move-Version $agentTarget (Join-Path $backupRoot "Agent")
    Move-Version $appTarget (Join-Path $backupRoot "App")
    Move-Version $identityTarget (Join-Path $backupRoot "Identity")
    Move-Version $managementTarget (Join-Path $backupRoot "Management")
    Write-UpdateLog ("Atomic directory backup completed: " + $backupRoot)

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
    if ($backupStarted) {
        try {
            Write-UpdateLog ("Restoring prior version by atomic directory move: " + $backupRoot)
            Stop-UpdateProcesses
            foreach ($folder in @("Agent","App","Identity","Management")) {
                $restoreSource = Join-Path $backupRoot $folder
                $restoreTarget = Join-Path $InstallRoot $folder
                if (Test-Path -LiteralPath $restoreSource) {
                    if (Test-Path -LiteralPath $restoreTarget) {
                        # The new target is flat and contains only newly installed files.
                        Remove-Item -LiteralPath $restoreTarget -Recurse -Force -ErrorAction Stop
                    }
                    Move-Version $restoreSource $restoreTarget
                }
            }
            Write-UpdateLog "Atomic rollback completed."
        } catch { Write-UpdateLog ("Rollback error: " + $_.Exception.ToString()) }
    }
    try { Start-ManagedService } catch { Write-UpdateLog ("Could not restart agent after failure: " + $_.Exception.ToString()) }
    Write-UpdateStatus "Update failed" $failure.Exception.Message
    exit 1
} finally {
    if ($acquired) { try { [void]$mutex.ReleaseMutex() } catch { } }
    $mutex.Dispose()
}
