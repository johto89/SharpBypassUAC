# SharpBypassUAC

C# tool for UAC bypass and token impersonation. Built with D/Invoke pattern — sensitive Win32 APIs are resolved at runtime to avoid static P/Invoke entries detectable by EDR.

No external dependencies. Builds with standalone `csc.exe` (no Visual Studio or NuGet required).

## Build

```
cd SharpBypassUAC
build.bat
```

Or manually:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /platform:anycpu /optimize+ /unsafe /out:SharpBypassUAC.exe Program.cs W.cs AlwaysNotify.cs FodHelper.cs EventVwr.cs Sdclt.cs ComputerDefaults.cs DiskCleanup.cs Slui.cs CmsTPLua.cs TokenImpersonation.cs
```

## Usage

### Prepare Command

Base64-encode the command to execute:

**Linux:**
```bash
echo -n "cmd.exe /c whoami > C:\out.txt" | base64
```

**PowerShell:**
```powershell
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("cmd.exe /c whoami > C:\out.txt"))
```

### UAC Bypass

```
SharpBypassUAC.exe -b <method> -e <base64command>
```

**Methods:**

| Method | Technique | Notes |
|--------|-----------|-------|
| `fodhelper` | ms-settings registry hijack → fodhelper.exe | Win10+ |
| `eventvwr` | mscfile registry hijack → eventvwr.exe | Win7+ |
| `computerdefaults` | ms-settings registry hijack → ComputerDefaults.exe | Win10+ |
| `sdclt` | Folder registry hijack → sdclt.exe | Win10 only |
| `slui` | exefile registry hijack → slui.exe | Win8+ |
| `diskcleanup` | Environment variable hijack → SilentCleanup task | Win10+ (command must end with `&& REM`) |
| `cmstp` | CMSTPLUA COM elevation (no registry modification) | Win7+ |

### Token Impersonation

```
SharpBypassUAC.exe -t <pid> -e <base64command>
```

Duplicates the token from a target process and creates a new process running under that token. Requires local admin privileges.

### Examples

**Fodhelper UAC bypass (reverse shell):**
```
SharpBypassUAC.exe -b fodhelper -e Y21kLmV4ZSAvYyBwb3dlcnNoZWxsIC1lbmMgLi4u
```

**CMSTPLUA COM elevation (no registry artifact):**
```
SharpBypassUAC.exe -b cmstp -e Y21kLmV4ZSAvYyB3aG9hbWk=
```

**Token impersonation (steal SYSTEM token from winlogon.exe):**
```
# Find winlogon PID
tasklist /FI "IMAGENAME eq winlogon.exe"

# Impersonate
SharpBypassUAC.exe -t 624 -e Y21kLmV4ZSAvYyB3aG9hbWk=
```

## Bypass Details

### Registry-Based Bypasses (fodhelper, eventvwr, computerdefaults, sdclt, slui)

These exploits hijack registry keys under `HKCU\Software\Classes\` that auto-elevating Windows binaries read when launched. The flow:

1. Write command to the target registry key
2. Launch the auto-elevate binary (inherits high integrity)
3. Binary reads the hijacked registry key and executes the command as elevated
4. Registry key is cleaned up after 10 seconds

Each bypass targets a different registry key and auto-elevate binary:

| Bypass | Registry Key | Binary |
|--------|-------------|--------|
| fodhelper | `HKCU\Software\Classes\ms-settings\Shell\Open\command` | fodhelper.exe |
| eventvwr | `HKCU\Software\Classes\mscfile\Shell\Open\command` | eventvwr.exe |
| computerdefaults | `HKCU\Software\Classes\ms-settings\Shell\Open\command` | ComputerDefaults.exe |
| sdclt | `HKCU\Software\Classes\Folder\shell\open\command` | sdclt.exe |
| slui | `HKCU\Software\Classes\exefile\Shell\Open\command` | slui.exe |

### DiskCleanup Bypass

Hijacks the `windir` environment variable in `HKCU\Environment`, then triggers the `SilentCleanup` scheduled task which runs with high integrity. The command must end with `&& REM` to comment out the rest of the task's command line.

### CMSTPLUA COM Elevation (cmstp)

Uses the CMSTPLUA COM object (`CLSID: {3E5FC7F9-9A51-4367-9063-A120244FBEC7}`) which has an auto-elevate manifest. The exploit:

1. Resolves `CoGetObject` from `ole32.dll` via D/Invoke (no static import)
2. Creates an elevation moniker: `Elevation:Administrator!new:{CLSID}`
3. Obtains elevated `ICMLuaUtil` interface via `CoGetObject`
4. Calls `ICMLuaUtil::ShellExec` to execute the command with high integrity

Advantages over registry-based bypasses:
- No registry modification (fewer forensic artifacts)
- No auto-elevate binary launched as intermediary
- Works on Windows 7 through Windows 11

The command is parsed as `<file> <arguments>`. For example, `powershell.exe -enc AAA` becomes file=`powershell.exe`, arguments=`-enc AAA`.

### Token Impersonation (-t)

Steals a token from a running process and spawns a new process under that identity. Uses D/Invoke for all Win32 API calls:

1. `OpenProcess` — open target process with `PROCESS_QUERY_LIMITED_INFORMATION`
2. `OpenProcessToken` — get the process token
3. `DuplicateTokenEx` — duplicate as a primary token with `SecurityImpersonation`
4. `CreateProcessWithTokenW` — create new process with the duplicated token

Requires local admin privileges. Common targets:
- **winlogon.exe** — runs as `NT AUTHORITY\SYSTEM`
- **lsass.exe** — runs as `NT AUTHORITY\SYSTEM`
- Any process running as a different user for lateral movement

## Architecture

```
SharpBypassUAC/
├── build.bat               # Standalone csc.exe build script
├── Program.cs              # Entry point, CLI argument parsing
├── W.cs                    # D/Invoke helper (LoadLibrary, GetProcAddress, XOR decode)
├── AlwaysNotify.cs         # UAC level check (exits if Always Notify)
├── FodHelper.cs            # fodhelper.exe registry hijack
├── EventVwr.cs             # eventvwr.exe registry hijack
├── ComputerDefaults.cs     # ComputerDefaults.exe registry hijack
├── Sdclt.cs                # sdclt.exe registry hijack (Win10 only)
├── Slui.cs                 # slui.exe registry hijack
├── DiskCleanup.cs          # SilentCleanup environment variable hijack
├── CmsTPLua.cs             # CMSTPLUA COM elevation via D/Invoke
└── TokenImpersonation.cs   # Token duplication via D/Invoke
```

## Evasion

| Technique | Description |
|-----------|-------------|
| D/Invoke | Sensitive APIs (CoGetObject, OpenProcess, DuplicateTokenEx, CreateProcessWithTokenW) resolved at runtime via `LoadLibrary` + `GetProcAddress` |
| XOR-encoded strings | API names and DLL names stored as XOR-encoded byte arrays, decoded at runtime |
| No external dependencies | Single-file build with `csc.exe`, no NuGet packages or build tools |
| Registry cleanup | All registry-based bypasses delete their keys after execution |

## Detections

### Registry-Based Bypasses

Monitor `HKCU\Software\Classes\` for new subkeys or value modifications. Specific keys:

- `HKCU\Software\Classes\ms-settings\Shell\Open\command` (fodhelper, computerdefaults)
- `HKCU\Software\Classes\mscfile\Shell\Open\command` (eventvwr)
- `HKCU\Software\Classes\Folder\shell\open\command` (sdclt)
- `HKCU\Software\Classes\exefile\Shell\Open\command` (slui)
- `HKCU\Environment\windir` (diskcleanup)

### CMSTPLUA

Monitor for COM elevation moniker usage with CMSTPLUA CLSID `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`. Sysmon Event ID 10 (process access) can detect the elevated COM object creation.

### Token Impersonation

Monitor for `OpenProcess` + `OpenProcessToken` + `DuplicateTokenEx` call chains targeting high-integrity processes. Sysmon Event ID 10 (process access) to sensitive processes like winlogon.exe.

## Credits

- **eventvwr**: [enigma0x3](https://github.com/enigma0x3) — [Invoke-EventVwrBypass.ps1](https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-EventVwrBypass.ps1)
- **fodhelper / computerdefaults**: [winscripting](https://github.com/winscripting) — [FodhelperBypass.ps1](https://github.com/winscripting/UAC-bypass)
- **sdclt**: [Emeric Nasi](http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass)
- **slui**: [bytecode77](https://github.com/bytecode77) — [slui-file-handler-hijack](https://github.com/bytecode77/slui-file-handler-hijack-privilege-escalation)
- **diskcleanup**: [enigma0x3](https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup/), [gushmazuko](https://github.com/gushmazuko/WinBypass)
- **CMSTPLUA**: Based on [UACME](https://github.com/hfiref0x/UACME/) project by [hfiref0x](https://github.com/hfiref0x)
