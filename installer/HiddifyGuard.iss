#ifndef MyAppVersion
  #define MyAppVersion "0.1.0"
#endif
#ifndef PublishDir
  #define PublishDir "..\dist\publish"
#endif

[Setup]
AppId={{7D78ED51-54A9-48D0-B674-90AF1D382DD2}
AppName=Hiddify Guard
AppVersion={#MyAppVersion}
AppPublisher=Hiddify Guard contributors
AppPublisherURL=https://github.com/ivanshcherbakov/hiddify-guard
DefaultDirName={autopf}\Hiddify Guard
DefaultGroupName=Hiddify Guard
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=HiddifyGuard-Setup-{#MyAppVersion}-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\HiddifyGuard.exe
CloseApplications=yes
RestartApplications=no
LicenseFile=..\LICENSE
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[CustomMessages]
english.AutoStart=Start in the system tray when I sign in (elevated scheduled task)
russian.AutoStart=Запускать в трее при входе в Windows (задача с повышенными правами)
english.DesktopIcon=Create a desktop shortcut
russian.DesktopIcon=Создать ярлык на рабочем столе
english.Recovery=Disable protection manually
russian.Recovery=Отключить защиту вручную
english.CleanupFailed=Protection could not be removed. No program files were deleted. Run HiddifyGuard.exe --uninstall-clean as administrator, then retry.
russian.CleanupFailed=Не удалось снять защиту. Файлы программы не удалены. Запустите HiddifyGuard.exe --uninstall-clean от администратора и повторите удаление.
english.MissingExe=HiddifyGuard.exe is missing. Restore the program using this installer before uninstalling, so the WFP filters can be removed.
russian.MissingExe=HiddifyGuard.exe отсутствует. Восстановите программу этим установщиком перед удалением, чтобы можно было снять WFP-фильтры.

[Tasks]
Name: "autostart"; Description: "{cm:AutoStart}"
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; Flags: unchecked

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.pdb"

[Icons]
Name: "{group}\Hiddify Guard"; Filename: "{app}\HiddifyGuard.exe"
Name: "{group}\{cm:Recovery}"; Filename: "{app}\HiddifyGuard.exe"; Parameters: "--disable"
Name: "{autodesktop}\Hiddify Guard"; Filename: "{app}\HiddifyGuard.exe"; Tasks: desktopicon

[UninstallRun]
; InitializeUninstall runs this first and vetoes file deletion on any failure.
Filename: "{app}\HiddifyGuard.exe"; Parameters: "--uninstall-clean"; Flags: runhidden waituntilterminated; Check: CleanupStillNeeded; RunOnceId: "HiddifyGuardWfpCleanup"

[Code]
var
  CleanupCompleted: Boolean;

function CleanupStillNeeded: Boolean;
begin
  Result := not CleanupCompleted;
end;

function UserTaskName: String;
begin
  Result := 'HiddifyGuard-' + GetUserNameString;
end;

procedure RemoveUserTask;
var
  Scheduler, Root: Variant;
begin
  try
    Scheduler := CreateOleObject('Schedule.Service');
    Scheduler.Connect;
    Root := Scheduler.GetFolder('\');
    Root.DeleteTask(UserTaskName, 0);
  except
    Log('No current-user startup task removed: ' + GetExceptionMessage);
  end;
end;

procedure RegisterStartupTask;
var
  Scheduler, Root, Task, Trigger, Action: Variant;
  UserName: String;
begin
  Scheduler := CreateOleObject('Schedule.Service');
  Scheduler.Connect;
  Root := Scheduler.GetFolder('\');
  Task := Scheduler.NewTask(0);
  UserName := GetEnv('USERDOMAIN') + '\' + GetUserNameString;
  Task.RegistrationInfo.Description := 'Hiddify Guard tray. Closing it does not disable protection.';
  Task.RegistrationInfo.Source := 'HiddifyGuard';
  Task.Principal.UserId := UserName;
  Task.Principal.LogonType := 3;  { TASK_LOGON_INTERACTIVE_TOKEN }
  Task.Principal.RunLevel := 1;  { TASK_RUNLEVEL_HIGHEST }
  Trigger := Task.Triggers.Create(9); { TASK_TRIGGER_LOGON }
  Trigger.UserId := UserName;
  Trigger.Enabled := True;
  Action := Task.Actions.Create(0);
  Action.Path := ExpandConstant('{app}\HiddifyGuard.exe');
  Action.Arguments := '--minimized';
  Action.WorkingDirectory := ExpandConstant('{app}');
  Task.Settings.DisallowStartIfOnBatteries := False;
  Task.Settings.StopIfGoingOnBatteries := False;
  Task.Settings.ExecutionTimeLimit := 'PT0S';
  Task.Settings.MultipleInstances := 2;
  Task.Settings.StartWhenAvailable := True;
  Root.RegisterTaskDefinition(UserTaskName, Task, 6, UserName, '', 3);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
  Exe: String;
begin
  Result := '';
  Exe := ExpandConstant('{app}\HiddifyGuard.exe');
  if FileExists(Exe) then
    if (not Exec(Exe, '--exit-tray', '', SW_HIDE, ewWaitUntilTerminated, Code)) or (Code <> 0) then
      Result := 'Close Hiddify Guard from the tray and retry. Protection remains active.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('autostart') then
      RegisterStartupTask
    else
      RemoveUserTask;
  end;
end;

function InitializeUninstall: Boolean;
var
  Code: Integer;
  Exe: String;
begin
  Result := False;
  CleanupCompleted := False;
  Exe := ExpandConstant('{app}\HiddifyGuard.exe');
  if not FileExists(Exe) then
  begin
    SuppressibleMsgBox(ExpandConstant('{cm:MissingExe}'), mbError, MB_OK, IDOK);
    Exit;
  end;
  if (not Exec(Exe, '--uninstall-clean', '', SW_HIDE, ewWaitUntilTerminated, Code)) or (Code <> 0) then
  begin
    SuppressibleMsgBox(ExpandConstant('{cm:CleanupFailed}'), mbError, MB_OK, IDOK);
    Exit;
  end;
  CleanupCompleted := True;
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Scheduler, Root, Tasks, Task: Variant;
  Index: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    try
      Scheduler := CreateOleObject('Schedule.Service');
      Scheduler.Connect;
      Root := Scheduler.GetFolder('\');
      Tasks := Root.GetTasks(1);
      for Index := Tasks.Count downto 1 do
      begin
        Task := Tasks.Item(Index);
        if (Task.Definition.RegistrationInfo.Source = 'HiddifyGuard') and
          (Task.Definition.Actions.Count = 1) then
          if CompareText(Task.Definition.Actions.Item(1).Path, ExpandConstant('{app}\HiddifyGuard.exe')) = 0 then
            Root.DeleteTask(Task.Name, 0);
      end;
    except
      Log('Startup-task cleanup: ' + GetExceptionMessage);
    end;
  end;
end;
