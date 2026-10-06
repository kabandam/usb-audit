param(
    [ValidateSet("Binaries", "Setup")]
    [string]$Target = "Binaries",
    [string]$PublishRoot = "dist/publish",
    [string]$SetupPath = "dist/SmartConsoleSetup.exe"
)

$ErrorActionPreference = "Stop"

$hasPfx = -not [string]::IsNullOrWhiteSpace($env:CODE_SIGN_PFX_BASE64)
$hasPassword = -not [string]::IsNullOrWhiteSpace($env:CODE_SIGN_PASSWORD)

if ($hasPfx -xor $hasPassword) {
    throw "Code signing is partially configured. Set both SMARTCONSOLE_CODESIGN_PFX_BASE64 and SMARTCONSOLE_CODESIGN_PASSWORD."
}

if (-not $hasPfx) {
    if ($Target -eq "Binaries") {
        Write-Warning "CRECCOM code-signing certificate is not configured. Build will remain SHA-256 verified but unsigned."
        if ($env:GITHUB_OUTPUT) {
            "enabled=false" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
        }
    }
    return
}

$pfxPath = Join-Path $env:TEMP "creccom-smart-console-codesign.pfx"
try {
    [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($env:CODE_SIGN_PFX_BASE64))

    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending |
        Select-Object -First 1

    if (-not $signtool) {
        throw "signtool.exe was not found on the Windows runner."
    }

    if ($Target -eq "Binaries") {
        $targets = Get-ChildItem $PublishRoot -Recurse -File | Where-Object {
            $_.Name -match '^(UsbAudit\..+|SmartConsole)\.(exe|dll)$'
        }

        if (-not $targets) {
            throw "No CRECCOM Smart Console binaries were found to sign."
        }
    }
    else {
        if (-not (Test-Path -LiteralPath $SetupPath)) {
            throw "Setup executable not found: $SetupPath"
        }
        $targets = @(Get-Item -LiteralPath $SetupPath)
    }

    foreach ($file in $targets) {
        & $signtool.FullName sign /fd SHA256 /td SHA256 /tr "https://timestamp.digicert.com" /f $pfxPath /p $env:CODE_SIGN_PASSWORD $file.FullName
        if ($LASTEXITCODE -ne 0) {
            throw "Code signing failed: $($file.FullName)"
        }

        & $signtool.FullName verify /pa /v $file.FullName
        if ($LASTEXITCODE -ne 0) {
            throw "Signature verification failed: $($file.FullName)"
        }
    }

    if ($Target -eq "Binaries" -and $env:GITHUB_OUTPUT) {
        $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($pfxPath, $env:CODE_SIGN_PASSWORD)
        "enabled=true" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
        "thumbprint=$($cert.Thumbprint)" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
        Write-Host "Signed $($targets.Count) CRECCOM binaries with certificate $($cert.Thumbprint)."
    }
}
finally {
    Remove-Item $pfxPath -Force -ErrorAction SilentlyContinue
}
