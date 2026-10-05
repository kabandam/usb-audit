param(
    [switch]$RemoveAuditData,
    [switch]$InstallerAuthorized
)

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"' + $PSCommandPath + '"'))
    if ($RemoveAuditData) { $args += "-RemoveAuditData" }
    if ($InstallerAuthorized) { $args += "-InstallerAuthorized" }
    Start-Process -FilePath "powershell.exe" -ArgumentList ($args -join " ") -Verb RunAs | Out-Null
    exit 0
}

function Test-SmartConsoleUninstallPassword {
    # Store only the SHA-256 verifier in the installed script. The requested
    # administrative uninstall password is never written in plaintext here.
    $expected = "06dc30c518d5c7ed4ed44ad653de60972eb502463809f733073354103444a281"
    $secure = Read-Host "Enter Smart Console administrative uninstall password" -AsSecureString
    $ptr = [IntPtr]::Zero
    $plain = $null
    try {
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($plain)
            $actual = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
            return $actual -eq $expected
        } finally {
            $sha.Dispose()
        }
    } finally {
        if ($ptr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
        $plain = $null
    }
}

if (-not $InstallerAuthorized -and -not (Test-SmartConsoleUninstallPassword)) {
    Write-Host "Incorrect administrative password. Smart Console was not removed." -ForegroundColor Red
    exit 5
}

if (Get-Service -Name "UsbAuditAgent" -ErrorAction SilentlyContinue) {
    Stop-Service "UsbAuditAgent" -Force -ErrorAction SilentlyContinue
    & sc.exe delete "UsbAuditAgent" | Out-Null
    Start-Sleep -Milliseconds 700
}

Get-Process -Name "SmartConsole" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process -Name "UsbAudit" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process -Name "UsbAudit.Identity" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Remove-Item (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\USB Audit.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Smart Console.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "USB Audit.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "Smart Console.lnk") -Force -ErrorAction SilentlyContinue
Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UsbAudit" -Recurse -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "CRECCOM USB Audit Identity" -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "CRECCOM Smart Console Identity" -Force -ErrorAction SilentlyContinue

# If this script is running from inside Program Files, remove the installation after PowerShell exits.
$installRoot = Join-Path $env:ProgramFiles "UsbAudit"
$cleanupCommand = "ping 127.0.0.1 -n 3 > nul & rmdir /s /q `"$installRoot`""
Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cleanupCommand" -WindowStyle Hidden

if ($RemoveAuditData) {
    Remove-Item (Join-Path $env:ProgramData "UsbAudit") -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Smart Console and its audit data were removed." -ForegroundColor Green
} else {
    Write-Host "Smart Console was removed. Audit data was preserved in C:\ProgramData\UsbAudit." -ForegroundColor Green
}
