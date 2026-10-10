# SharpBypassUAC

C# tool for UAC bypass and token impersonation. Built with D/Invoke pattern — sensitive Win32 APIs are resolved at runtime to avoid static P/Invoke entries detectable by EDR.

No external dependencies. Builds with standalone `csc.exe` (no Visual Studio or NuGet required).

---

## Table of Contents

- [Background](#background)
- [Build](#build)
- [Quick Reference](#quick-reference)
- [Techniques](#techniques)
  - [Registry Hijack Bypasses](#1-registry-hijack-bypasses)
    - [fodhelper](#fodhelper)
    - [eventvwr](#eventvwr)
    - [computerdefaults](#computerdefaults)
    - [sdclt](#sdclt)
    - [slui](#slui)
  - [Environment Variable Hijack — DiskCleanup](#2-environment-variable-hijack--diskcleanup)
  - [File System Primitive Abuse — Intel ShaderCache](#3-file-system-primitive-abuse--intel-shadercache)
  - [COM Elevation — CMSTPLUA](#4-com-elevation--cmstplua)
  - [Token Impersonation](#5-token-impersonation)
- [Evasion](#evasion)
- [Detection Guide](#detection-guide)
- [Architecture](#architecture)
- [Credits](#credits)

---

## Background

### What is UAC?

User Account Control (UAC) is a security feature introduced in Windows Vista that prevents applications from making system-level changes without explicit administrator approval. When a standard-integrity process requests elevated privileges, Windows displays a consent prompt (the familiar dimmed desktop dialog). UAC operates through **integrity levels** — a mandatory access control mechanism in the Windows security model:

| Integrity Level | Token Type | Typical Process | Can Write To |
|----------------|------------|-----------------|--------------|
| Low | Restricted | Sandboxed browser tabs, `%LOCALAPPDATA%Low` writers | `%LOCALAPPDATA%Low`, low-labeled objects only |
| Medium | Filtered admin token | Most user applications (explorer.exe, notepad) | `HKCU`, user profile, user-owned files |
| High | Full admin token | Elevated processes (Run as Administrator) | `HKLM`, `C:\Windows\System32`, system services |
| System | SYSTEM token | OS services (winlogon.exe, lsass.exe) | Everything |

When a user in the local Administrators group logs in, Windows creates **two tokens**: a filtered token (medium integrity, used by default) and a full token (high integrity, used only after consent). UAC bypass techniques trick Windows into granting the full token without showing the consent prompt.

### Auto-Elevation

Windows designates certain signed Microsoft binaries as **auto-elevate** — they receive high integrity automatically without a UAC prompt. This is controlled by the `autoElevate` property in the executable's embedded manifest:

```xml
<requestedExecutionLevel level="highestAvailable" uiAccess="false" />
<autoElevate>true</autoElevate>
```

Auto-elevation only works when:
1. The binary is signed by Microsoft
2. Located in a trusted directory (`C:\Windows\System32`, etc.)
3. UAC is **not** set to "Always Notify" (the highest setting)

UAC bypass techniques exploit these auto-elevating binaries by controlling what they execute after they receive their elevated token — through registry hijacks, environment variable manipulation, DLL search order abuse, or COM object elevation.

### D/Invoke Pattern

Traditional C# tools use P/Invoke (`[DllImport]`) to call Win32 APIs, which creates static entries in the .NET assembly's metadata. EDR products scan these entries to flag suspicious API usage (`OpenProcess`, `DuplicateTokenEx`, etc.).

D/Invoke avoids this by resolving APIs at runtime:

```
LoadLibrary("kernel32.dll") → GetProcAddress(handle, "CreateProcessA") → Marshal.GetDelegateForFunctionPointer()
```

SharpBypassUAC goes further by XOR-encoding the API and DLL name strings, so static analysis cannot extract the API names from the binary. Only `LoadLibrary` and `GetProcAddress` themselves appear as static imports — two universally used APIs that cannot be flagged without massive false positives.

---

## Build

```
cd SharpBypassUAC
build.bat
```

Or manually:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /platform:anycpu /optimize+ /unsafe /out:SharpBypassUAC.exe Program.cs W.cs AlwaysNotify.cs FodHelper.cs EventVwr.cs Sdclt.cs ComputerDefaults.cs DiskCleanup.cs Slui.cs CmsTPLua.cs TokenImpersonation.cs IntelShaderCache.cs
```

---

## Quick Reference

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

| Method | Category | Technique | Compatibility |
|--------|----------|-----------|---------------|
| `fodhelper` | Registry hijack | ms-settings → fodhelper.exe | Win10+ |
| `eventvwr` | Registry hijack | mscfile → eventvwr.exe | Win7+ |
| `computerdefaults` | Registry hijack | ms-settings → ComputerDefaults.exe | Win10+ |
| `sdclt` | Registry hijack | Folder → sdclt.exe | Win10 only |
| `slui` | Registry hijack | exefile → slui.exe | Win8+ |
| `diskcleanup` | Env variable hijack | windir → SilentCleanup task | Win10+ |
| `shadercache` | File system + DLL hijack | Junction + symlink → oci.dll | x64, Intel GPU |
| `cmstp` | COM elevation | CMSTPLUA COM object | Win7+ |

### Token Impersonation

```
SharpBypassUAC.exe -t <pid> -e <base64command>
```

### Examples

```bash
# Fodhelper UAC bypass
SharpBypassUAC.exe -b fodhelper -e Y21kLmV4ZSAvYyBwb3dlcnNoZWxsIC1lbmMgLi4u

# CMSTPLUA COM elevation (no registry artifact)
SharpBypassUAC.exe -b cmstp -e Y21kLmV4ZSAvYyB3aG9hbWk=

# Token impersonation (steal SYSTEM token from winlogon.exe)
tasklist /FI "IMAGENAME eq winlogon.exe"
SharpBypassUAC.exe -t 624 -e Y21kLmV4ZSAvYyB3aG9hbWk=
```

---

## Techniques

### 1. Registry Hijack Bypasses

#### Theory

Windows Shell uses a layered registry lookup to determine which program handles a given protocol or file type. When a user opens `ms-settings:` or `.mscfile`, the Shell searches in this order:

```
HKCU\Software\Classes\<handler>\Shell\Open\command    ← user override (medium integrity writable)
HKCR\<handler>\Shell\Open\command                     ← machine default (requires admin)
```

`HKCU` takes priority over `HKCR`. Since `HKCU\Software\Classes` is writable at medium integrity, any unprivileged process can plant a handler override. When an auto-elevating binary (e.g., `fodhelper.exe`) launches and internally invokes a protocol like `ms-settings:`, Windows resolves it through the hijacked `HKCU` key — and the command in that key inherits the auto-elevated high-integrity token.

This is a **token inheritance** attack: the attacker never elevates directly, instead they make an already-elevated process execute attacker-controlled code.

The general attack flow:

```
[Medium Integrity]                         [High Integrity]
                                          
Write HKCU\..\command = payload   ──→   Auto-elevate binary starts
                                              │
                                              ├─ Reads HKCU handler override
                                              │
                                              └─ Executes payload as HIGH integrity
                                          
Sleep 10s → Delete HKCU key (cleanup)
```

#### Individual Methods

##### fodhelper

**Binary:** `C:\Windows\System32\fodhelper.exe` (Features On Demand helper)

**Registry Key:** `HKCU\Software\Classes\ms-settings\Shell\Open\command`

**How it works:** `fodhelper.exe` has `autoElevate=true` in its manifest. On launch, it invokes the `ms-settings:` protocol to open Windows Settings. By planting a command under the `ms-settings` handler in `HKCU`, the attacker's payload runs instead — with high integrity.

An additional value `DelegateExecute` (empty string) must be set under the same key. Without it, Windows ignores the custom `command` value and falls back to `HKCR`.

**Compatibility:** Windows 10+

**Discovered by:** [winscripting](https://github.com/winscripting/UAC-bypass)

##### eventvwr

**Binary:** `C:\Windows\System32\eventvwr.exe` (Event Viewer)

**Registry Key:** `HKCU\Software\Classes\mscfile\Shell\Open\command`

**How it works:** `eventvwr.exe` auto-elevates and then opens `eventvwr.msc` — a `.msc` (Microsoft Management Console snap-in) file. Windows resolves `.msc` via the `mscfile` handler. By hijacking this handler in `HKCU`, the attacker's command executes instead of the Event Viewer snap-in.

Unlike `ms-settings`-based bypasses, this does not require the `DelegateExecute` value.

**Compatibility:** Windows 7+ (one of the oldest known bypasses still working on some builds)

**Discovered by:** [enigma0x3](https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-EventVwrBypass.ps1)

##### computerdefaults

**Binary:** `C:\Windows\System32\ComputerDefaults.exe` (Default Programs settings)

**Registry Key:** `HKCU\Software\Classes\ms-settings\Shell\Open\command`

**How it works:** Same `ms-settings:` hijack as `fodhelper`. `ComputerDefaults.exe` also auto-elevates and invokes `ms-settings:`, so the same registry key works. This provides an alternative binary in case `fodhelper.exe` is monitored or blocked.

**Compatibility:** Windows 10+

**Discovered by:** [winscripting](https://github.com/winscripting/UAC-bypass)

##### sdclt

**Binary:** `C:\Windows\System32\sdclt.exe` (Windows Backup)

**Registry Key:** `HKCU\Software\Classes\Folder\shell\open\command`

**How it works:** `sdclt.exe` auto-elevates and opens a Folder-type shell item. By hijacking the `Folder` handler's `open` command in `HKCU`, the attacker controls what executes. Requires the `DelegateExecute` empty value.

**Compatibility:** Windows 10 only — Microsoft patched this on Windows 11 by removing `sdclt.exe`'s auto-elevate manifest.

**Discovered by:** [Emeric Nasi](http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass)

##### slui

**Binary:** `C:\Windows\System32\slui.exe` (Software Licensing UI)

**Registry Key:** `HKCU\Software\Classes\exefile\Shell\Open\command`

**How it works:** `slui.exe` auto-elevates and then launches another `.exe` file. By hijacking the `exefile` handler in `HKCU`, the attacker intercepts the executable launch. This hijacks the general `.exe` file handler, which is broader than protocol-specific handlers — it affects any `.exe` invocation that goes through the Shell until the cleanup removes the key.

**Compatibility:** Windows 8+

**Discovered by:** [bytecode77](https://github.com/bytecode77/slui-file-handler-hijack-privilege-escalation)

#### Registry Bypass Summary

| Method | Registry Key | Binary | DelegateExecute |
|--------|-------------|--------|-----------------|
| fodhelper | `HKCU\..\ms-settings\Shell\Open\command` | fodhelper.exe | Required (empty) |
| eventvwr | `HKCU\..\mscfile\Shell\Open\command` | eventvwr.exe | Not needed |
| computerdefaults | `HKCU\..\ms-settings\Shell\Open\command` | ComputerDefaults.exe | Required (empty) |
| sdclt | `HKCU\..\Folder\shell\open\command` | sdclt.exe | Required (empty) |
| slui | `HKCU\..\exefile\Shell\Open\command` | slui.exe | Not needed |

---

### 2. Environment Variable Hijack — DiskCleanup

#### Theory

Some Windows scheduled tasks run with high integrity but resolve paths through **user-controllable environment variables**. The `SilentCleanup` task (`\Microsoft\Windows\DiskCleanup\SilentCleanup`) is configured to run with "highest available" privileges and executes:

```
%windir%\System32\cleanmgr.exe /autoclean /d %systemdrive%
```

The key insight: `%windir%` is resolved from the process environment, and Windows allows per-user environment variable overrides in `HKCU\Environment`. A value set there takes priority over the system-wide `windir` in `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`.

By setting `HKCU\Environment\windir` to an attacker-controlled command, the task scheduler resolves `%windir%` to that command. The `\System32\cleanmgr.exe /autoclean /d C:` suffix is appended to the attacker's command, so the command must end with `&& REM` to comment out the trailing arguments.

#### Attack Flow

```
[Medium Integrity]
     │
     ├─ Set HKCU\Environment\windir = "cmd.exe /c payload && REM"
     │
     ├─ schtasks /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I
     │      │
     │      └─ Task Scheduler launches task with HIGH integrity
     │              │
     │              └─ Resolves: "cmd.exe /c payload && REM\System32\cleanmgr.exe /autoclean..."
     │                              ↑ REM comments out everything after &&
     │
     └─ Sleep 10s → Delete HKCU\Environment\windir
```

#### Requirements

- Windows 10+ (the `SilentCleanup` task must exist and be configured for highest privileges)
- Command **must** end with `&& REM`
- UAC not set to "Always Notify"

**Discovered by:** [enigma0x3](https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup/), [gushmazuko](https://github.com/gushmazuko/WinBypass)

---

### 3. File System Primitive Abuse — Intel ShaderCache

#### Theory

This technique chains three Windows file system primitives — **NTFS junctions**, **object manager symlinks**, and **DLL search order hijacking** — to achieve an arbitrary file write into `C:\Windows\System32` from medium integrity, without any registry modification.

**NTFS Junction (Reparse Point)**

A junction is a directory-level symbolic link implemented as an NTFS reparse point. When a process accesses `C:\A\file.txt` and `C:\A` is a junction pointing to `C:\B`, the I/O manager transparently redirects the access to `C:\B\file.txt`. Junctions can be created by any user on directories they own — no admin required. Critically, junctions can also point to **object manager namespaces** using the `\??\` prefix (e.g., `\??\GLOBALROOT\RPC CONTROL`).

**Object Manager Symlink (DosDevice)**

The Windows Object Manager maintains a namespace separate from the file system. The `\RPC CONTROL\` directory in this namespace is writable by any authenticated user. `DefineDosDeviceW` with `DDD_RAW_TARGET_PATH` flag creates a symlink in this namespace — for example, mapping `\RPC CONTROL\shader_1234.bin` → `C:\Windows\System32\oci.dll`. When a file I/O operation traverses a junction into `\RPC CONTROL\` and hits this symlink, the I/O manager follows it to the final target path, and the write lands in System32.

**DLL Search Order Hijack**

`oci.dll` (Oracle Call Interface) is a DLL that certain Microsoft binaries attempt to load but is not present in a default Windows installation. `comexp.msc` (Component Services MMC snap-in) is an auto-elevating binary that loads `oci.dll` from `System32` if it exists. By placing a malicious `oci.dll` there, the attacker's code runs with high integrity when `comexp.msc` is launched.

**The complete chain uses an innocent third party — the Intel GPU driver** — as the write primitive. The driver's ShaderCache directory (`%LOCALAPPDATA%Low\Intel\ShaderCache`) has `Full Control` for Authenticated Users and is written to by auto-elevated processes (Task Manager triggers shader compilation). By replacing the ShaderCache directory with a junction, the elevated driver write is redirected through the junction → symlink chain into System32.

#### Attack Flow

```
[Step 1] Launch TaskManager (auto-elevates)
         │
         └─ Intel GPU driver writes shader file to ShaderCache
            Capture the filename (e.g., "shader_abc123.bin")

[Step 2] Kill sihost.exe, ShellHost.exe (they hold handles to ShaderCache)
         Clear ShaderCache directory contents

[Step 3] Create NTFS junction:
         %LOCALAPPDATA%Low\Intel\ShaderCache ──→ \??\GLOBALROOT\RPC CONTROL

[Step 4] Create object manager symlink via DefineDosDeviceW:
         \RPC CONTROL\shader_abc123.bin ──→ C:\Windows\System32\oci.dll

[Step 5] Launch TaskManager again
         │
         └─ Intel driver writes to ShaderCache\shader_abc123.bin
            │
            ├─ Junction redirects to \RPC CONTROL\shader_abc123.bin
            │
            └─ Symlink redirects to C:\Windows\System32\oci.dll
               → oci.dll is created in System32 (owned by elevated process)

[Step 6] Overwrite oci.dll content with minimal x64 PE DLL payload
         (built at runtime in memory, calls CreateProcessA with attacker's command)

[Step 7] Launch comexp.msc (auto-elevates, loads oci.dll)
         → Payload DllMain executes with HIGH integrity
```

#### Requirements

- **x64 only** — the payload DLL is a minimal x64 PE built at runtime
- **Intel GPU driver** must be installed (creates the ShaderCache directory)
- UAC not set to "Always Notify"

#### Advantages

- No registry modification — leaves no `HKCU` artifacts
- Uses legitimate OS file system primitives (junctions, DosDevice symlinks)
- The write to System32 comes from a trusted Microsoft process (Task Manager), not from the attacker process

#### Limitations

- Requires Intel GPU hardware/driver
- Race condition on ShaderCache directory (may need retry in contested environments)
- Kills `sihost.exe` / `ShellHost.exe` temporarily (restarted by Windows automatically)

> **Warning:** The `shadercache` method causes **visible system disruption** during execution. Killing `sihost.exe` and `ShellHost.exe` temporarily breaks the taskbar, Start menu, and notification area — users on the target machine will notice immediately. Additionally, if cleanup fails, a persistent `oci.dll` remains in `C:\Windows\System32` and will be loaded by any process that imports it, potentially causing stability issues or repeated payload execution. This technique also generates significant forensic artifacts (NTFS journal entries, Prefetch files, AmCache records, Sysmon events) that survive cleanup. **This method is recommended primarily for SOC/Blue Team detection capability assessment** — it provides a realistic, high-artifact attack chain ideal for validating detection rules, Sysmon configurations, and incident response procedures. It is **not recommended for covert red team operations** due to its noisy footprint and user-visible side effects.

**Based on:** [Intel GPU driver ShaderCache directory junction technique](https://mansk1es.gitbook.io/sce-blog/windows-internals/uac-bypass-with-intel-graphics-directory) by mansk1es

---

### 4. COM Elevation — CMSTPLUA

#### Theory

Windows COM (Component Object Model) supports an **elevation moniker** mechanism that allows a process to instantiate a COM object in an elevated context — effectively requesting a high-integrity COM server without showing a UAC prompt, provided the COM class has `autoElevate=true` in its registration.

The elevation moniker string follows this format:

```
Elevation:Administrator!new:{CLSID}
```

When passed to `CoGetObject`, the COM runtime:
1. Checks if the CLSID's registration has the auto-elevation flag
2. If yes, instantiates the COM object in a new elevated (high integrity) process
3. Returns an interface pointer to the caller

The **CMSTPLUA** COM object (`CLSID: {3E5FC7F9-9A51-4367-9063-A120244FBEC7}`) is part of the Connection Manager profile installer. It has `autoElevate=true` in its registration and exposes the `ICMLuaUtil` interface, which includes a `ShellExec` method — a general-purpose process launcher that runs the specified command as the elevated COM server, inheriting its high-integrity token.

Unlike registry-based bypasses, no file system or registry artifacts are created. The elevated code path exists entirely within the COM infrastructure. This makes CMSTPLUA one of the cleanest UAC bypass techniques from a forensic perspective.

#### Attack Flow

```
[Medium Integrity Process]
     │
     ├─ Resolve CoGetObject from ole32.dll via D/Invoke
     │
     ├─ CoGetObject("Elevation:Administrator!new:{3E5FC7F9-...}", IID_ICMLuaUtil)
     │      │
     │      └─ COM runtime auto-elevates → returns elevated ICMLuaUtil
     │
     └─ ICMLuaUtil::ShellExec(command, arguments, ...)
            │
            └─ Command runs with HIGH integrity
```

The command is parsed as `<file> <arguments>`. For example, `powershell.exe -enc AAA` becomes file=`powershell.exe`, arguments=`-enc AAA`.

#### Requirements

- Windows 7 through Windows 11
- UAC not set to "Always Notify"

#### Advantages

- No registry modification (cleanest forensic footprint of all methods)
- No auto-elevate binary launched as intermediary
- No file system artifacts
- Broadest Windows version compatibility

**Based on:** [UACME](https://github.com/hfiref0x/UACME/) project by [hfiref0x](https://github.com/hfiref0x)

---

### 5. Token Impersonation

#### Theory

Every Windows process runs under a **security token** that defines its identity and privileges. Token impersonation is a technique where an attacker duplicates the token from a higher-privileged process and uses it to spawn a new process under that identity.

The Windows API provides a direct path for this:

```
OpenProcess(PID)             → Process handle
OpenProcessToken(handle)     → Token handle
DuplicateTokenEx(token)      → New primary token (independent copy)
CreateProcessWithTokenW(dup) → New process running under stolen identity
```

`DuplicateTokenEx` creates a **standalone copy** of the token — the new process is not linked to the original. Even if the source process exits, the duplicated token remains valid.

This is not a UAC bypass — it requires the caller to already have local administrator privileges (specifically `SeDebugPrivilege` or sufficient access to the target process). It is used for **privilege escalation within an elevated context**: from local admin to SYSTEM, or from one user identity to another.

#### Attack Flow

```
[High Integrity / Admin]
     │
     ├─ OpenProcess(winlogon_pid, PROCESS_QUERY_LIMITED_INFORMATION)
     │
     ├─ OpenProcessToken(process_handle, TOKEN_DUPLICATE)
     │
     ├─ DuplicateTokenEx(token, SecurityImpersonation, TokenPrimary)
     │      │
     │      └─ Independent copy of SYSTEM token
     │
     └─ CreateProcessWithTokenW(duplicated_token, command)
            │
            └─ New process runs as NT AUTHORITY\SYSTEM
```

#### Common Targets

| Process | Identity | Use Case |
|---------|----------|----------|
| `winlogon.exe` | `NT AUTHORITY\SYSTEM` | General SYSTEM elevation |
| `lsass.exe` | `NT AUTHORITY\SYSTEM` | SYSTEM elevation (higher risk — may trigger EDR) |
| Any user process | Target user | Lateral identity movement |

#### Requirements

- Local administrator privileges (required for `OpenProcess` on SYSTEM-level processes)
- Target process must be running

---

## Evasion

| Technique | Description |
|-----------|-------------|
| D/Invoke | Sensitive APIs (`CoGetObject`, `OpenProcess`, `DuplicateTokenEx`, `CreateProcessWithTokenW`, `CreateFileW`, `DeviceIoControl`, `DefineDosDeviceW`) resolved at runtime via `LoadLibrary` + `GetProcAddress` — no static P/Invoke metadata |
| XOR-encoded strings | API names, DLL names, and registry paths stored as XOR-encoded byte arrays with per-module keys, decoded only at call time |
| Runtime PE construction | The `shadercache` method builds its payload DLL entirely in memory using `BinaryWriter` — no DLL file is dropped from resources or downloaded |
| No external dependencies | Single-file build with `csc.exe`, no NuGet packages or build tools that could be fingerprinted |
| Registry cleanup | All registry-based bypasses delete their keys after a 10-second delay |

---

## Detection Guide

### Registry-Based Bypasses (fodhelper, eventvwr, computerdefaults, sdclt, slui)

**Sysmon Event ID 12/13** (Registry object created/value set)

Monitor `HKCU\Software\Classes\` for creation of shell handler overrides:

| Key to Monitor | Methods |
|----------------|---------|
| `HKCU\Software\Classes\ms-settings\Shell\Open\command` | fodhelper, computerdefaults |
| `HKCU\Software\Classes\mscfile\Shell\Open\command` | eventvwr |
| `HKCU\Software\Classes\Folder\shell\open\command` | sdclt |
| `HKCU\Software\Classes\exefile\Shell\Open\command` | slui |

**Sysmon Event ID 1** (Process creation)

Alert on auto-elevating binaries (`fodhelper.exe`, `eventvwr.exe`, `ComputerDefaults.exe`, `sdclt.exe`, `slui.exe`) spawning unexpected child processes (e.g., `cmd.exe`, `powershell.exe`).

### DiskCleanup

**Sysmon Event ID 12/13** — Monitor `HKCU\Environment\windir` for value creation or modification.

**Sysmon Event ID 1** — Alert on `schtasks.exe` invoking `SilentCleanup` when `HKCU\Environment\windir` is set.

### Intel ShaderCache

| Indicator | Sysmon Event | Detail |
|-----------|-------------|--------|
| NTFS junction in ShaderCache | Event ID 11 (FileCreate) | Reparse point creation in `%LOCALAPPDATA%Low\Intel\ShaderCache` |
| `oci.dll` written to System32 | Event ID 11 (FileCreate) | `C:\Windows\System32\oci.dll` — this file should not exist on a default installation |
| `oci.dll` loaded by mmc.exe | Event ID 7 (ImageLoaded) | Unexpected DLL load by `mmc.exe` / `comexp.msc` |
| Shell processes killed | Event ID 5 (ProcessTerminated) | `sihost.exe` and `ShellHost.exe` terminated and respawned in rapid succession |

`DefineDosDeviceW` calls creating symlinks under `\RPC CONTROL\` are hard to monitor directly at the Sysmon level, but the presence of `oci.dll` in System32 is a strong post-execution indicator.

### CMSTPLUA

**Sysmon Event ID 10** (ProcessAccess) — Monitor for COM elevation moniker usage with CMSTPLUA CLSID `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`.

**Sysmon Event ID 1** — Alert on `DllHost.exe` (COM surrogate) spawning unexpected child processes after being invoked with the CMSTPLUA CLSID.

### Token Impersonation

**Sysmon Event ID 10** (ProcessAccess) — Monitor `OpenProcess` calls targeting high-integrity processes (`winlogon.exe`, `lsass.exe`) with `PROCESS_QUERY_LIMITED_INFORMATION` or `PROCESS_QUERY_INFORMATION` access rights.

**Sysmon Event ID 1** — Alert on new processes whose token user (`NT AUTHORITY\SYSTEM`) does not match the parent process's user, which indicates a cross-identity token usage.

---

## Architecture

```
SharpBypassUAC/
├── build.bat               # Standalone csc.exe build script
├── Program.cs              # Entry point, CLI argument parsing
├── W.cs                    # D/Invoke core (LoadLibrary, GetProcAddress, GetDelegate<T>, XOR decode)
├── AlwaysNotify.cs         # UAC level check — aborts if set to Always Notify
│
├── FodHelper.cs            # Registry hijack: ms-settings → fodhelper.exe
├── EventVwr.cs             # Registry hijack: mscfile → eventvwr.exe
├── ComputerDefaults.cs     # Registry hijack: ms-settings → ComputerDefaults.exe
├── Sdclt.cs                # Registry hijack: Folder → sdclt.exe (Win10 only)
├── Slui.cs                 # Registry hijack: exefile → slui.exe
├── DiskCleanup.cs          # Environment variable hijack → SilentCleanup task
│
├── CmsTPLua.cs             # CMSTPLUA COM elevation via D/Invoke
├── IntelShaderCache.cs     # Intel ShaderCache junction + DLL hijack via D/Invoke
└── TokenImpersonation.cs   # Token duplication via D/Invoke
```

---

## Credits

- **eventvwr**: [enigma0x3](https://github.com/enigma0x3) — [Invoke-EventVwrBypass.ps1](https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-EventVwrBypass.ps1)
- **fodhelper / computerdefaults**: [winscripting](https://github.com/winscripting) — [FodhelperBypass.ps1](https://github.com/winscripting/UAC-bypass)
- **sdclt**: [Emeric Nasi](http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass)
- **slui**: [bytecode77](https://github.com/bytecode77) — [slui-file-handler-hijack](https://github.com/bytecode77/slui-file-handler-hijack-privilege-escalation)
- **diskcleanup**: [enigma0x3](https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup/), [gushmazuko](https://github.com/gushmazuko/WinBypass)
- **shadercache**: Based on [Intel GPU driver ShaderCache directory junction technique](https://mansk1es.gitbook.io/sce-blog/windows-internals/uac-bypass-with-intel-graphics-directory) by mansk1es
- **CMSTPLUA**: Based on [UACME](https://github.com/hfiref0x/UACME/) project by [hfiref0x](https://github.com/hfiref0x)
