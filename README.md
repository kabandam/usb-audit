# CRECCOM Security Console — USB Audit V1.2

CRECCOM Security Console is a modular endpoint-security platform. USB Audit is its first module: a Windows 10/11 administrator audit application for organization-managed PCs that records removable USB storage connections and observed file activity, with an optional protected audit copy of completed USB writes.

The central React console is deployed at `secure.creccommw.org`. Cloud data is isolated in the dedicated Supabase project `creccom-security` (`pgbipustotixwahmotvu`).

## What it records

- USB device connection and disconnection history
- Drive letter, volume label, model and serial/volume identifier when Windows exposes them
- Logged-on Windows user available through Windows management information
- Files observed being written to a removable USB volume
- Timestamp, file name/path, size and SHA-256 hash
- Optional retained audit copy
- USB file deletion events (configurable)
- CSV export of the audit log
- SHA-256-linked audit records so simple historical modifications can be detected by the dashboard verifier

## Evidence boundary

A `PC -> USB` record means the agent observed the completed file on a monitored removable USB volume and successfully inspected it. The service does **not** invent an original PC source path. Ordinary `FileSystemWatcher` notifications do not prove which source file supplied the bytes.

A normal folder watcher also cannot prove every `USB -> PC` copy because reading a USB file does not necessarily modify the USB volume. The UI therefore does not falsely label such reads as confirmed transfers. A future advanced capture engine can feed stronger source/destination I/O evidence into the same audit model.

## Privacy and administration

USB Audit is intentionally visible and administrator-controlled. It contains no hidden-mode or remote-exfiltration feature. File retention is **disabled by default**. If retention is enabled, copies are stored under `C:\ProgramData\UsbAudit\Archive` and access is restricted to LocalSystem and Administrators.

Use file retention only where your organization has an appropriate notice, purpose and retention policy.

## Branding

The WPF interface requests the **Inter** font family throughout the app. Font files are not bundled. Install Google Inter on the Windows workstation for the intended branded appearance; Windows will substitute a system font if Inter is absent.

## Recommended installation: UsbAuditSetup.exe

Each GitHub release builds a conventional Windows installer named:

`UsbAuditSetup.exe`

A user downloads the latest Setup file, double-clicks it, approves the Windows administrator prompt, and the installer:

1. Installs the USB Audit desktop application.
2. Installs and starts the `USB Audit Agent` Windows service.
3. Creates Start-menu and desktop shortcuts.
4. Creates the protected audit-data folders.
5. Registers USB Audit for normal Windows uninstall.
6. Leaves automatic GitHub updates enabled by default.

After installation, users do **not** need to download Setup again for ordinary upgrades. The background agent checks GitHub Releases and installs newer stable releases automatically.

The project does not currently include a commercial code-signing certificate. Until signing is configured, Windows may identify test installers as an unknown publisher. Published ZIP and Setup assets have SHA-256 checksum files so deployment teams can verify package integrity.

## Permanent one-click online installer

The repository also contains:

`UsbAuditOnlineInstaller.cmd`

This is a single double-click bootstrap installer. It does not contain a fixed app version. Instead it:

1. Requests administrator permission.
2. Reads the latest stable release from `kabandam/usb-audit`.
3. Downloads `UsbAudit-win-x64.zip` and `UsbAudit-win-x64.zip.sha256`.
4. Verifies the SHA-256 checksum before extracting anything.
5. Runs the packaged installer script.
6. Starts the USB Audit background service.

This means the same `UsbAuditOnlineInstaller.cmd` file can be kept on an IT deployment drive and used later to install whatever stable version is current at that time.

The configured GitHub repository must be public for this token-free installer and updater design. If the source repository must remain private, use a separate public release-only repository or an organization-managed authenticated update service rather than embedding a GitHub personal access token on endpoints.

## Automatic GitHub updates

Default configuration:

- Update checks: enabled
- Automatic installation: enabled
- Check interval: every 1 hour
- Release repository: `kabandam/usb-audit`
- Release asset: `UsbAudit-win-x64.zip`
- Verification asset: `UsbAudit-win-x64.zip.sha256`

The Windows Service performs the check, so the dashboard does not need to be open. The Settings page shows the installed version, latest version, last check, and update status, and includes **Check for updates now**.

The updater compares the installed version with the latest GitHub Release, verifies the downloaded package with either GitHub's SHA-256 asset digest or the published `.sha256` file, stages the update under `C:\ProgramData\UsbAudit\Updates`, backs up the current App, Agent and management scripts, stops the service/dashboard, applies the release, restarts monitoring, and rolls back if replacement fails.

## Push-to-release workflow

The included `.github\workflows\windows-build.yml` treats `main` as the production branch. Each push to `main`:

1. Builds self-contained Windows x64 App and Agent binaries.
2. Assigns a version such as `1.2.12` using the GitHub Actions run number.
3. Produces `UsbAudit-win-x64.zip` and its SHA-256 checksum.
4. Compiles `UsbAuditSetup.exe` with Inno Setup and produces its SHA-256 checksum.
5. Publishes the ZIP, Setup EXE, checksums, and online installer in a GitHub Release.
6. Marks that release as latest so installed PCs can discover it.

Use feature branches for unfinished changes. Merge/push to `main` only when a change is ready to reach installed machines.

## Source build requirements

For source builds:

- Windows 10 or Windows 11, 64-bit
- Administrator rights for installation
- .NET 8 SDK
- Inno Setup 6 if you also want to create `UsbAuditSetup.exe` locally
- Internet access during first restore if required Microsoft NuGet packages are not already cached

Published builds are self-contained and do not require a separate .NET runtime.

## Build on Windows

From PowerShell in the repository root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\Build-UsbAudit.ps1
```

Outputs include:

- `dist\UsbAudit-win-x64.zip`
- `dist\UsbAudit-win-x64.zip.sha256`
- `dist\UsbAuditSetup.exe` when Inno Setup 6 is installed
- `dist\UsbAuditSetup.exe.sha256`

## Manual packaged install

If you are using the ZIP rather than Setup.exe, extract it and run as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-UsbAudit.ps1
```

The installation creates:

- `C:\Program Files\UsbAudit\Agent\UsbAudit.Agent.exe`
- `C:\Program Files\UsbAudit\App\UsbAudit.exe`
- `C:\Program Files\UsbAudit\Management`
- Windows service: `UsbAuditAgent`
- Start-menu and desktop shortcut: `USB Audit`
- Protected audit storage: `C:\ProgramData\UsbAudit`

## Settings

Open **USB Audit > Settings** as an administrator. Settings include:

- Keep an audit copy of transferred files: Off by default
- Maximum individual archive file size: 100 MB default
- Retention period: 30 days default
- Archive quota: 10 GB default
- Log USB file deletions: On by default
- Check GitHub automatically
- Install stable updates automatically
- GitHub repository and update interval

## Storage format

Audit events are append-only JSON Lines. New records include a previous-record hash and a record hash; the dashboard periodically verifies this chain. This is tamper-evidence, not a guarantee against a fully privileged administrator who deliberately reconstructs the entire log.

Audit events:

`C:\ProgramData\UsbAudit\Data\events.jsonl`

Connected-device state:

`C:\ProgramData\UsbAudit\Data\connected-devices.json`

Configuration:

`C:\ProgramData\UsbAudit\settings.json`

## Uninstall

USB Audit can be removed through Windows installed-app settings or with:

```powershell
.\Uninstall-UsbAudit.ps1
```

Audit data is preserved by default. To explicitly remove retained audit data too:

```powershell
.\Uninstall-UsbAudit.ps1 -RemoveAuditData
```

## Planned advanced capture engine

The shared event model already has source/destination fields so a later Windows file-system minifilter or equivalent I/O capture component can add stronger correlation for PC-to-USB and USB-to-PC transfers without replacing the dashboard or historical data format.

## Repository status

The production source and release channel is `kabandam/usb-audit`. The online installer and installed updater are configured to retrieve the latest stable release from this repository.
