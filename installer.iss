[Setup]
; Basic Application Information
AppName=NMAP Insight
AppVersion=1.0
DefaultDirName={autopf}\NMAP_Insight
DefaultGroupName=NMAP Insight

; FOR ADMIN/ROOT PRIVILEGES, force Windows to show the UAC prompt when running installer
PrivilegesRequired=admin

; Output settings
OutputDir=dist
OutputBaseFilename=NMAP_Insight_Setup
Compression=lzma
SolidCompression=yes

[Files]
; Include the executable we just built with PyInstaller
Source: "dist\main.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Create shortcuts in the Start Menu and on the Desktop
Name: "{group}\NMAP Insight"; Filename: "{app}\main.exe"
Name: "{autodesktop}\NMAP Insight"; Filename: "{app}\main.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"

[Run]
; Option to run the app immediately after installation finishes
Filename: "{app}\main.exe"; Description: "Launch NMAP Insight"; Flags: nowait postinstall skipifsilent
