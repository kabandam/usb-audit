param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [string]$Version = "1.2.0"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"
$publish = Join-Path $dist "publish"

Write-Host "USB Audit build" -ForegroundColor Cyan
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw ".NET 8 SDK was not found. Install the .NET 8 SDK and run this script again."
}

$sdkVersion = & dotnet --version
if (-not $sdkVersion.StartsWith("8.")) {
    Write-Warning "This project targets .NET 8. Detected SDK: $sdkVersion"
}

if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
New-Item -ItemType Directory -Path $publish | Out-Null

& dotnet restore (Join-Path $root "UsbAudit.sln")
if ($LASTEXITCODE -ne 0) { throw "dotnet restore failed." }

$agentOut = Join-Path $publish "Agent"
$appOut = Join-Path $publish "App"

& dotnet publish (Join-Path $root "src\UsbAudit.Agent\UsbAudit.Agent.csproj") `
    -c $Configuration -r $Runtime --self-contained true -p:Version=$Version -o $agentOut
if ($LASTEXITCODE -ne 0) { throw "Agent publish failed." }

& dotnet publish (Join-Path $root "src\UsbAudit.App\UsbAudit.App.csproj") `
    -c $Configuration -r $Runtime --self-contained true -p:Version=$Version -o $appOut
if ($LASTEXITCODE -ne 0) { throw "Desktop app publish failed." }

foreach ($name in @("Install-UsbAudit.ps1", "Uninstall-UsbAudit.ps1", "Apply-UsbAuditUpdate.ps1", "Install-Latest-UsbAudit.ps1")) {
    Copy-Item (Join-Path $root "scripts\$name") $publish
}
Copy-Item (Join-Path $root "README.md") $publish

$zip = Join-Path $dist "UsbAudit-win-x64.zip"
Compress-Archive -Path (Join-Path $publish "*") -DestinationPath $zip -Force
$zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$zipHash  UsbAudit-win-x64.zip" | Set-Content "$zip.sha256" -Encoding ascii
Write-Host "Built: $zip" -ForegroundColor Green

$iscc = Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
if (Test-Path $iscc) {
    $iss = Join-Path $root "installer\UsbAuditSetup.iss"
    & $iscc "/DSourceRoot=$publish" "/DAppVersion=$Version" "/DOutputDir=$dist" $iss
    if ($LASTEXITCODE -ne 0) { throw "Setup.exe build failed." }
    $setup = Join-Path $dist "UsbAuditSetup.exe"
    $setupHash = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLowerInvariant()
    "$setupHash  UsbAuditSetup.exe" | Set-Content "$setup.sha256" -Encoding ascii
    Write-Host "Built: $setup" -ForegroundColor Green
} else {
    Write-Warning "Inno Setup 6 was not found. ZIP build is complete; install Inno Setup to also produce UsbAuditSetup.exe."
}
