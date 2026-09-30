#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#ifndef BuildArch
  #define BuildArch "win-x64"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\BFRS"
#endif
#ifndef OutputDir
  #define OutputDir "..\artifacts"
#endif
#ifndef IconFile
  #define IconFile "bfrs.ico"
#endif

#if BuildArch == "win-arm64"
  #define AllowedArch "arm64"
#else
  #define AllowedArch "x64compatible and not arm64"
#endif

[Setup]
AppId={{D5FE4D0E-8A2B-4B77-AEE0-CABDBCC7F5AA}
AppName=BFRS
AppVersion={#MyAppVersion}
AppVerName=BFRS {#MyAppVersion}
AppPublisher=BFRS Project
DefaultDirName={autopf}\BFRS
DefaultGroupName=BFRS
DisableProgramGroupPage=yes
OutputDir={#OutputDir}
OutputBaseFilename=BFRS-{#MyAppVersion}-{#BuildArch}-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed={#AllowedArch}
ArchitecturesInstallIn64BitMode={#AllowedArch}
PrivilegesRequired=lowest
UninstallDisplayIcon={app}\BFRS.exe
SetupIconFile={#IconFile}

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\BFRS"; Filename: "{app}\BFRS.exe"
Name: "{userdesktop}\BFRS"; Filename: "{app}\BFRS.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\BFRS.exe"; Description: "Launch BFRS"; Flags: nowait postinstall skipifsilent
