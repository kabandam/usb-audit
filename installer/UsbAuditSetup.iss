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
VersionInfoVersion={#AppVersion}
VersionInfoProductVersion={#AppVersion}
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
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File ""{tmp}\UsbAuditPayload\Install-UsbAudit.ps1"" -SkipUninstallRegistration"; StatusMsg: "Installing CRECCOM Smart Console and starting background monitoring..."; Flags: waituntilterminated runhidden
Filename: "{autopf}\UsbAudit\App\SmartConsole.exe"; Description: "Open Smart Console"; StatusMsg: "Opening Smart Console..."; Flags: nowait skipifsilent

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File ""{autopf}\UsbAudit\Management\Uninstall-UsbAudit.ps1"" -InstallerAuthorized"; Flags: waituntilterminated runhidden; RunOnceId: "UsbAuditServiceAndFiles"


[Code]
const
  SmartConsoleUninstallPasswordHash = '06dc30c518d5c7ed4ed44ad653de60972eb502463809f733073354103444a281';

function PromptForUninstallPassword(): Boolean;
var
  Form: TSetupForm;
  PromptLabel: TNewStaticText;
  PasswordEdit: TPasswordEdit;
  OkButton: TNewButton;
  CancelButton: TNewButton;
  ModalResult: Integer;
begin
  Form := CreateCustomForm(ScaleX(360), ScaleY(150), False, False);
  try
    Form.Caption := 'Smart Console protected uninstall';
    Form.CenterOnShow := True;

    PromptLabel := TNewStaticText.Create(Form);
    PromptLabel.Parent := Form;
    PromptLabel.Left := ScaleX(16);
    PromptLabel.Top := ScaleY(16);
    PromptLabel.Width := ScaleX(328);
    PromptLabel.Height := ScaleY(34);
    PromptLabel.AutoSize := False;
    PromptLabel.WordWrap := True;
    PromptLabel.Caption :=
      'Enter the CRECCOM administrative uninstall password to remove Smart Console:';

    PasswordEdit := TPasswordEdit.Create(Form);
    PasswordEdit.Parent := Form;
    PasswordEdit.Left := ScaleX(16);
    PasswordEdit.Top := ScaleY(60);
    PasswordEdit.Width := ScaleX(328);
    PasswordEdit.Height := ScaleY(23);
    PasswordEdit.Password := True;
    PasswordEdit.MaxLength := 64;

    OkButton := TNewButton.Create(Form);
    OkButton.Parent := Form;
    OkButton.Caption := 'OK';
    OkButton.ModalResult := mrOk;
    OkButton.Default := True;
    OkButton.Left := ScaleX(184);
    OkButton.Top := ScaleY(103);
    OkButton.Width := ScaleX(76);
    OkButton.Height := ScaleY(25);

    CancelButton := TNewButton.Create(Form);
    CancelButton.Parent := Form;
    CancelButton.Caption := 'Cancel';
    CancelButton.ModalResult := mrCancel;
    CancelButton.Cancel := True;
    CancelButton.Left := ScaleX(268);
    CancelButton.Top := ScaleY(103);
    CancelButton.Width := ScaleX(76);
    CancelButton.Height := ScaleY(25);

    Form.ActiveControl := PasswordEdit;
    ModalResult := Form.ShowModal;

    Result :=
      (ModalResult = mrOk) and
      (CompareText(
        GetSHA256OfString(PasswordEdit.Text),
        SmartConsoleUninstallPasswordHash) = 0);
  finally
    Form.Free;
  end;
end;

function InitializeUninstall(): Boolean;
begin
  Result := PromptForUninstallPassword();
  if not Result then
    MsgBox(
      'Incorrect or missing administrative password. Smart Console will remain installed.',
      mbError,
      MB_OK);
end;
