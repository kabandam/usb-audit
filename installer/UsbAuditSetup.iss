#ifndef SourceRoot
  #define SourceRoot "..\dist\publish"
#endif
#ifndef AppVersion
  #define AppVersion "1.2.0"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

[Setup]
AppId={{36A5C57A-2E3F-4BA9-A40D-8B2C90B8722D}
AppName=USB Audit
AppVersion={#AppVersion}
AppVerName=USB Audit {#AppVersion}
DefaultDirName={autopf}\UsbAudit
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=UsbAuditSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
Uninstallable=yes
CreateUninstallRegKey=yes
CloseApplications=yes
RestartApplications=no
SetupLogging=yes

[Files]
Source: "{#SourceRoot}\*"; DestDir: "{tmp}\UsbAuditPayload"; Flags: recursesubdirs createallsubdirs deleteafterinstall

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{tmp}\UsbAuditPayload\Install-UsbAudit.ps1"" -SkipUninstallRegistration"; StatusMsg: "Installing USB Audit and starting the monitoring service..."; Flags: waituntilterminated runhidden

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{autopf}\UsbAudit\Management\Uninstall-UsbAudit.ps1"""; Flags: waituntilterminated runhidden; RunOnceId: "UsbAuditServiceAndFiles"
