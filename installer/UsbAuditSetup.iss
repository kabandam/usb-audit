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
AppName=Smart Console
AppVersion={#AppVersion}
AppVerName=Smart Console {#AppVersion}
AppPublisher=CRECCOM
AppPublisherURL=https://creccommw.org
AppSupportURL=https://creccommw.org
AppUpdatesURL=https://secure.creccommw.org
VersionInfoCompany=CRECCOM
VersionInfoDescription=CRECCOM Smart Console Installer
VersionInfoProductName=Smart Console
UninstallDisplayName=Smart Console
UninstallDisplayIcon={autopf}\UsbAudit\App\SmartConsole.exe
DefaultDirName={autopf}\UsbAudit
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=SmartConsoleSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile={#SourceRoot}\Branding\CRECCOM.ico
Uninstallable=yes
CreateUninstallRegKey=yes
CloseApplications=yes
RestartApplications=no
SetupLogging=yes

[Files]
Source: "{#SourceRoot}\*"; DestDir: "{tmp}\UsbAuditPayload"; Flags: recursesubdirs createallsubdirs deleteafterinstall

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{tmp}\UsbAuditPayload\Install-UsbAudit.ps1"" -SkipUninstallRegistration"; StatusMsg: "Installing CRECCOM Smart Console and starting background monitoring..."; Flags: waituntilterminated runhidden
Filename: "{autopf}\UsbAudit\App\SmartConsole.exe"; Description: "Open Smart Console"; StatusMsg: "Opening Smart Console..."; Flags: nowait skipifsilent

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{autopf}\UsbAudit\Management\Uninstall-UsbAudit.ps1"" -InstallerAuthorized"; Flags: waituntilterminated runhidden; RunOnceId: "UsbAuditServiceAndFiles"


[Code]
const
  SmartConsoleUninstallPasswordHash = '06dc30c518d5c7ed4ed44ad653de60972eb502463809f733073354103444a281';

function InitializeUninstall(): Boolean;
var
  Password: String;
begin
  Password := InputBox(
    'Smart Console protected uninstall',
    'Enter the CRECCOM administrative uninstall password to remove Smart Console:',
    '');

  Result := CompareText(
    GetSHA256OfString(Password),
    SmartConsoleUninstallPasswordHash) = 0;

  if not Result then
    MsgBox(
      'Incorrect administrative password. Smart Console will remain installed.',
      mbError,
      MB_OK);
end;
