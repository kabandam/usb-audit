param(
    [switch]$RemoveAuditData
)

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"' + $PSCommandPath + '"'))
    if ($RemoveAuditData) { $args += "-RemoveAuditData" }
    Start-Process -FilePath "powershell.exe" -ArgumentList ($args -join " ") -Verb RunAs | Out-Null
    exit 0
}

if (Get-Service -Name "UsbAuditAgent" -ErrorAction SilentlyContinue) {
    Stop-Service "UsbAuditAgent" -Force -ErrorAction SilentlyContinue
    & sc.exe delete "UsbAuditAgent" | Out-Null
    Start-Sleep -Milliseconds 700
}

Get-Process -Name "UsbAudit" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Remove-Item (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\USB Audit.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "USB Audit.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UsbAudit" -Recurse -Force -ErrorAction SilentlyContinue

# If this script is running from inside Program Files, remove the installation after PowerShell exits.
$installRoot = Join-Path $env:ProgramFiles "UsbAudit"
$cleanupCommand = "ping 127.0.0.1 -n 3 > nul & rmdir /s /q `"$installRoot`""
Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cleanupCommand" -WindowStyle Hidden

if ($RemoveAuditData) {
    Remove-Item (Join-Path $env:ProgramData "UsbAudit") -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "USB Audit and its audit data were removed." -ForegroundColor Green
} else {
    Write-Host "USB Audit was removed. Audit data was preserved in C:\ProgramData\UsbAudit." -ForegroundColor Green
}
