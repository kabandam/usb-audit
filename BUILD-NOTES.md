# Build notes — USB Audit V1.2

This source package was assembled and statically validated in a Linux artifact environment. XML/XAML project files can be checked here, but WPF, Windows Services, PowerShell service installation and Inno Setup compilation require a Windows runner or Windows test PC.

## New V1.2 deployment path

V1.2 adds two user-facing installation paths:

1. **`UsbAuditSetup.exe`** — conventional one-click Windows setup compiled by GitHub Actions with Inno Setup. It contains the release version being published.
2. **`UsbAuditOnlineInstaller.cmd`** — one-file bootstrap installer that always fetches the latest stable public GitHub Release, verifies `UsbAudit-win-x64.zip.sha256`, and installs the verified package.

The installed service then handles future automatic updates, so users normally install only once.

## GitHub release outputs

A push to `main` is configured to publish:

- `UsbAudit-win-x64.zip`
- `UsbAudit-win-x64.zip.sha256`
- `UsbAuditSetup.exe`
- `UsbAuditSetup.exe.sha256`
- `UsbAuditOnlineInstaller.cmd`

The app updater can use GitHub's asset digest when available and falls back to the published ZIP checksum file. Update rollback now includes App, Agent and management scripts.

## First Windows validation

Before broad deployment, use one disposable/test PC and USB drive:

1. Create the intended public `kabandam/usb-audit` repository and push this source to `main`.
2. Confirm GitHub Actions completes and the release contains all five assets listed above.
3. Download `UsbAuditSetup.exe`, double-click it and approve UAC.
4. Confirm `USB Audit Agent` is running in `services.msc`.
5. Confirm USB Audit appears in Windows installed apps and Start/desktop shortcuts work.
6. Plug in a test USB drive and confirm device history updates.
7. Copy a non-sensitive test file to the USB drive and confirm a PC → USB record with SHA-256.
8. Publish a second release and confirm the installed PC updates automatically while preserving `C:\ProgramData\UsbAudit` data.
9. Uninstall and confirm audit data is preserved unless removal was explicitly requested.
10. Test `UsbAuditOnlineInstaller.cmd` on a second clean PC and confirm it installs the newest release rather than a hard-coded version.

## Code signing

The build does not currently sign `UsbAuditSetup.exe`, the desktop executable, or service executable with a trusted publisher certificate. Production deployment should add organization-controlled Windows code signing to reduce unknown-publisher/SmartScreen friction and provide stronger publisher authenticity.

Do not use retained-file mode on production workstations until the organization's privacy, notice and retention requirements are approved.
