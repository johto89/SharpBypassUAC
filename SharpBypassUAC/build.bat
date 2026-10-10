@echo off
echo [*] Building SharpBypassUAC...

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe ^
  /target:exe ^
  /platform:anycpu ^
  /optimize+ ^
  /unsafe ^
  /out:SharpBypassUAC.exe ^
  Program.cs ^
  W.cs ^
  AlwaysNotify.cs ^
  FodHelper.cs ^
  EventVwr.cs ^
  Sdclt.cs ^
  ComputerDefaults.cs ^
  DiskCleanup.cs ^
  Slui.cs ^
  CmsTPLua.cs ^
  TokenImpersonation.cs ^
  IntelShaderCache.cs

if %ERRORLEVEL% == 0 (
    echo [+] Build successful: SharpBypassUAC.exe
) else (
    echo [!] Build failed
)
