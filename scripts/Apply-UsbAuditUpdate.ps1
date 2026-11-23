param(
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$StagingRoot,
    [string]$ServiceName = "UsbAuditAgent",
    [ValidateSet("Upgrade", "Repair", "UpgradeRepair")]
    [string]$InstallMode = "UpgradeRepair",
    [switch]$InstallerInitiated
)

$ErrorActionPreference = "Stop"
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
# An old installation can be incomplete; rebuild the original root instead
# of requiring a separate reinstall or losing its existing ProgramData state.
New-Item -ItemType Directory -Path $InstallRoot -Force -ErrorAction Stop | Out-Null
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


function Backup-EndpointState {
    # Persistent state is OUTSIDE the executable directories and is never
    # deleted by the in-place updater. Keep an extra copy of sensitive
    # enrollment/settings metadata in case the legacy endpoint was damaged.
    $backup = Join-Path $dataRoot ("UpdateBackups\" + (Get-Date -Format "yyyyMMdd-HHmmss-fff"))
    $files = @(
        "settings.json",
        "Data\cloud-state.json",
        "Data\terminal-status.json",
        "Data\connection-settings-guard.json",
        "Data\endpoint-policy.json",
        "Data\location-state.json",
        "Data\received-applications.json",
        "Data\last-event.json"
    )
    foreach ($relative in $files) {
        $source = Join-Path $dataRoot $relative
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { continue }
        $destination = Join-Path $backup $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force -ErrorAction Stop | Out-Null
        Copy-Item -LiteralPath $source -Destination $destination -ErrorAction Stop
        if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne
            (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash) {
            throw "Could not verify the preserved endpoint state: $relative"
        }
    }
    Write-UpdateLog "Existing endpoint configuration backed up without changing enrollment or audit data."
}

function Copy-MissingLegacyData([string]$legacyRoot) {
    # Import known legacy data layouts only. NEVER overwrite populated
    # ProgramData files (especially terminal credentials and audit hash chains).
    if (-not (Test-Path -LiteralPath $legacyRoot -PathType Container)) { return }

    $legacySettings = Join-Path $legacyRoot "settings.json"
    $currentSettings = Join-Path $dataRoot "settings.json"
    if (-not (Test-Path -LiteralPath $currentSettings) -and
         (Test-Path -LiteralPath $legacySettings -PathType Leaf)) {
        # Reject unreadable JSON rather than replacing a working identity.
        try {
            $null = Get-Content -LiteralPath $legacySettings -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            Copy-Item -LiteralPath $legacySettings -Destination $currentSettings -ErrorAction Stop
            Write-UpdateLog ("Restored legacy settings from " + $legacyRoot)
        } catch {
            Write-UpdateLog ("Legacy settings could not be migrated safely: " + $_.Exception.Message)
        }
    }

    foreach ($folder in @("Data", "Archive")) {
        $source = Join-Path $legacyRoot $folder
        $destinationRoot = Join-Path $dataRoot $folder
        if (-not (Test-Path -LiteralPath $source -PathType Container)) { continue }
        foreach ($file in Get-ChildItem -LiteralPath $source -File -Recurse -ErrorAction Stop) {
            $relative = $file.FullName.Substring($source.TrimEnd('\').Length).TrimStart('\')
            $destination = Join-Path $destinationRoot $relative
            if (Test-Path -LiteralPath $destination) { continue }
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force -ErrorAction Stop | Out-Null
            Copy-Item -LiteralPath $file.FullName -Destination $destination -ErrorAction Stop
            Write-UpdateLog ("Recovered legacy file " + $folder + "\" + $relative)
        }
    }
}

function Restore-And-ProtectState {
    New-Item -ItemType Directory -Path $dataRoot -Force -ErrorAction Stop | Out-Null
    foreach ($folder in @("Data", "Archive", "Updates")) {
        New-Item -ItemType Directory -Path (Join-Path $dataRoot $folder) -Force -ErrorAction Stop | Out-Null
    }
    # Known earlier layouts might leave data next to app files.
    foreach ($legacyRoot in @($InstallRoot, (Join-Path $InstallRoot "App"), (Join-Path $InstallRoot "Agent"))) {
        Copy-MissingLegacyData $legacyRoot
    }
    Backup-EndpointState
}

function Repair-Shortcuts {
    $appExe = Join-Path $appTarget "SmartConsole.exe"
    try {
        $shell = New-Object -ComObject WScript.Shell
        $startMenu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Smart Console.lnk"
        $desktop = Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "Smart Console.lnk"
        foreach ($shortcutPath in @($startMenu, $desktop)) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $shortcutPath) -Force -ErrorAction Stop | Out-Null
            $shortcut = $shell.CreateShortcut($shortcutPath)
            $shortcut.TargetPath = $appExe
            $shortcut.WorkingDirectory = $appTarget
            $shortcut.Description = "CRECCOM Smart Console"
            $shortcut.Save()
        }
        Write-UpdateLog "Smart Console shortcuts verified and restored."
    } catch {
        # A missing desktop shortcut must not undo an otherwise healthy agent.
        Write-UpdateLog ("Shortcut restoration warning: " + $_.Exception.Message)
    }
    try {
        $uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UsbAudit"
        if (Test-Path $uninstallKey) {
            $version = (Get-Item (Join-Path $appTarget "SmartConsole.exe")).VersionInfo.ProductVersion
            Set-ItemProperty -Path $uninstallKey -Name DisplayVersion -Value $version -ErrorAction Stop
            Set-ItemProperty -Path $uninstallKey -Name InstallLocation -Value $InstallRoot -ErrorAction Stop
            Set-ItemProperty -Path $uninstallKey -Name DisplayIcon -Value $appExe -ErrorAction Stop
        }
    } catch {
        Write-UpdateLog ("Installed-program metadata warning: " + $_.Exception.Message)
    }
}

function Stop-UpdateProcesses {
    # The previous script left UsbAudit.Identity running, locking the Identity
    # executable and making Copy-Item fail. Always stop it before copying.
    Get-Process -Name "SmartConsole","UsbAudit.Identity","UsbAudit" -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-UpdateLog ("Agent service " + $ServiceName + " is missing; repair will recreate it.")
        return
    }
    if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        Write-UpdateLog ("Stopping service " + $ServiceName)
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(45))
    }
    Start-Sleep -Seconds 2
    if ((Get-Service -Name $ServiceName -ErrorAction Stop).Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
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
    $agentExe = Join-Path $agentTarget "UsbAudit.Agent.exe"
    if (-not (Test-Path -LiteralPath $agentExe)) {
        throw "The repaired agent executable is missing."
    }
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        New-Service -Name $ServiceName -BinaryPathName ('"' + $agentExe + '"') -DisplayName "Smart Console Agent" -StartupType Automatic -ErrorAction Stop | Out-Null
        Write-UpdateLog ("Recreated missing Windows agent service " + $ServiceName)
    } else {
        & sc.exe config $ServiceName binPath= ('"' + $agentExe + '"') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to restore Smart Console Agent service binary path." }
    }
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
        # An interactive setup must not report success until its own upgrade
        # actually runs. Keep the legacy unattended updater behavior unchanged.
        if ($InstallerInitiated) { exit 5 }
        exit 0
    }
    Write-UpdateLog ("Starting verified in-place " + $InstallMode + ". Staging=" + $StagingRoot)
    if (-not (Test-Path (Join-Path $agentSource "UsbAudit.Agent.exe")) -or
        -not (Test-Path (Join-Path $appSource "SmartConsole.exe")) -or
        -not (Test-Path (Join-Path $identitySource "UsbAudit.Identity.exe"))) {
        throw "Staged update is incomplete: Agent, App or Identity executable is missing."
    }

    Stop-UpdateProcesses
    # Read any old files BEFORE moving the existing executable directories.
    # ProgramData and its enrollment identity remain untouched in-place.
    Restore-And-ProtectState

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
    # Upgrade replaces the program files with the newer version. Repair (or
    # UpgradeRepair) also regenerates shortcuts and installed-program metadata.
    # In every mode, enrollment, settings, and event logs remain under
    # ProgramData and are never overwritten by executable replacement.
    if ($InstallMode -in @("Repair", "UpgradeRepair")) { Repair-Shortcuts }
    # LocalSystem runs in session 0: do not launch a hidden desktop app there.
    # The signed-in user can reopen the Smart Console shortcut normally.
    Write-UpdateStatus "Updated" ("Smart Console " + $InstallMode + " completed; the verified CRECCOM release is installed and the agent service restarted.")
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
                } elseif ($installationTouched -and (Test-Path -LiteralPath $restoreTarget)) {
                    # This folder was missing before the update; remove only
                    # newly created program files when a fresh install fails.
                    Remove-Item -LiteralPath $restoreTarget -Recurse -Force -ErrorAction Stop
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
