<#
.SYNOPSIS
    UAC Bypass Posture & Artifact Auditor.

.DESCRIPTION
    Audits a Windows host for (a) configuration that makes it susceptible to
    known UAC bypass techniques and (b) on-disk / registry / event log artifacts
    left behind by common bypass primitives:

    Registry hijack:  fodhelper, eventvwr, sdclt, computerdefaults, slui
    Env variable:     DiskCleanup (windir hijack), .NET Profiler (COR_PROFILER #39)
    File system:      Intel ShaderCache junction + DLL hijack (oci.dll)
    DLL hijack:       MSDT/sdiagnhost BluetoothDiagnosticUtil.dll (#72)
    COM elevation:    CMSTPLUA, ElevatedFactoryServer (#74), DiagCpl factory (#75)
    ALPC:             AppInfo RPC + debug object elevation (#59)
    Token abuse:      SeDebugPrivilege / token impersonation surface

    Additional checks: phantom DLL slots in System32, NTFS reparse points in
    known attack paths, Sysmon configuration validation, historical event log
    artifact scanning, and high-privilege scheduled task enumeration.

    Findings are emitted as structured objects so they can be piped to
    Export-Csv / ConvertTo-Json for reporting. Use -AsJson for machine output.

    Read-only by design: the script never writes to the registry or filesystem
    and never loads untrusted binaries into the process.

.NOTES
    Author : Johto Robbie
    License: GPLv3

    Severity legend:
        Critical / High / Medium / Low / Info

.EXAMPLE
    .\UAC-BypassAudit.ps1

.EXAMPLE
    .\UAC-BypassAudit.ps1 -AsJson | Out-File audit.json -Encoding utf8
#>

[CmdletBinding()]
param(
    [switch]$AsJson,
    # Suspicious command-string patterns used to flag hijacked shell commands.
    [string[]]$SuspiciousCommandPatterns = @(
        'cmd(\.exe)?', 'powershell', 'pwsh', 'wscript', 'cscript', 'mshta',
        'rundll32', 'regsvr32', '\\temp\\', '%temp%', '\\appdata\\',
        '\\users\\public\\', 'certutil', 'bitsadmin', '-enc', '-e\s', 'FromBase64'
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helpers -----------------------------------------------------------------

$script:Findings = [System.Collections.Generic.List[object]]::new()

function New-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail,
        [object]$Evidence
    )
    $script:Findings.Add([PSCustomObject]@{
        Timestamp = (Get-Date).ToString('o')
        Category  = $Category
        Severity  = $Severity
        Title     = $Title
        Detail    = $Detail
        Evidence  = $Evidence
    })
}

function Test-IsAdministrator {
    # True only when the current process token is actually elevated (High IL+).
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($id)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ProcessIntegrityLevel {
    # Resolve the integrity level of the current token from its mandatory-label SID,
    # which is language-independent (unlike parsing `whoami /groups` text).
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $labelSid = ($id.Groups | Where-Object {
            $_.Value -like 'S-1-16-*'
        } | Select-Object -First 1).Value

        switch ($labelSid) {
            'S-1-16-4096'  { 'Low' }
            'S-1-16-8192'  { 'Medium' }
            'S-1-16-8448'  { 'MediumPlus' }
            'S-1-16-12288' { 'High' }
            'S-1-16-16384' { 'System' }
            default        { "Unknown ($labelSid)" }
        }
    } catch {
        'Unknown'
    }
}

function Get-EmbeddedManifestText {
    # Extract the embedded RT_MANIFEST (resource type 24) text from a PE without
    # executing it, by loading the file as a resource-only module.
    param([Parameter(Mandatory)][string]$Path)

    $signature = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class ManifestReader {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr LoadLibraryEx(string f, IntPtr h, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FreeLibrary(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr FindResource(IntPtr h, IntPtr name, IntPtr type);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LoadResource(IntPtr h, IntPtr res);
    [DllImport("kernel32.dll")]
    static extern IntPtr LockResource(IntPtr data);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint SizeofResource(IntPtr h, IntPtr res);

    const uint LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020;
    const uint LOAD_LIBRARY_AS_DATAFILE       = 0x00000002;

    public static string Read(string path) {
        IntPtr hMod = LoadLibraryEx(path, IntPtr.Zero,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
        if (hMod == IntPtr.Zero) return null;
        try {
            // RT_MANIFEST = 24, CREATEPROCESS_MANIFEST_RESOURCE_ID = 1
            IntPtr hRes = FindResource(hMod, (IntPtr)1, (IntPtr)24);
            if (hRes == IntPtr.Zero) return string.Empty;
            uint size = SizeofResource(hMod, hRes);
            IntPtr hData = LoadResource(hMod, hRes);
            if (hData == IntPtr.Zero || size == 0) return string.Empty;
            IntPtr p = LockResource(hData);
            byte[] buf = new byte[size];
            Marshal.Copy(p, buf, 0, (int)size);
            return Encoding.UTF8.GetString(buf);
        } finally {
            FreeLibrary(hMod);
        }
    }
}
'@
    if (-not ('ManifestReader' -as [type])) {
        Add-Type -TypeDefinition $signature -ErrorAction Stop
    }
    try { return [ManifestReader]::Read($Path) } catch { return $null }
}

function Test-FileMicrosoftSigned {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Microsoft')
    } catch {
        return $false
    }
}

#endregion Helpers --------------------------------------------------------------

#region Checks ------------------------------------------------------------------

function Invoke-UACLevelCheck {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    try {
        $s = Get-ItemProperty -Path $path -ErrorAction Stop
    } catch {
        New-Finding -Category 'UAC Config' -Severity 'Info' `
            -Title 'Cannot read UAC policy' -Detail $_.Exception.Message
        return
    }

    function Get-Prop($obj, $name) {
        $p = $obj.PSObject.Properties[$name]
        if ($p) { $p.Value } else { $null }
    }
    $enableLUA     = Get-Prop $s 'EnableLUA'
    $consentAdmin  = Get-Prop $s 'ConsentPromptBehaviorAdmin'
    $secureDesktop = Get-Prop $s 'PromptOnSecureDesktop'

    if ($enableLUA -eq 0) {
        New-Finding -Category 'UAC Config' -Severity 'Critical' `
            -Title 'UAC fully disabled (EnableLUA=0)' `
            -Detail 'All processes for admins run at High IL; UAC provides no boundary.' `
            -Evidence @{ EnableLUA = $enableLUA }
    }
    # ConsentPromptBehaviorAdmin: 0 = elevate without prompting (vulnerable),
    # 2 = prompt on secure desktop (strongest), 5 = default (prompt for non-Windows binaries)
    if ($consentAdmin -eq 0) {
        New-Finding -Category 'UAC Config' -Severity 'High' `
            -Title 'Admin consent prompt disabled (ConsentPromptBehaviorAdmin=0)' `
            -Detail 'Elevation occurs silently; auto-elevate bypasses are trivial.' `
            -Evidence @{ ConsentPromptBehaviorAdmin = $consentAdmin }
    }
    if ($secureDesktop -eq 0) {
        New-Finding -Category 'UAC Config' -Severity 'Medium' `
            -Title 'Secure desktop disabled (PromptOnSecureDesktop=0)' `
            -Detail 'Consent prompt is spoofable from the user desktop.' `
            -Evidence @{ PromptOnSecureDesktop = $secureDesktop }
    }
    if ($enableLUA -ne 0 -and $consentAdmin -ne 0 -and $secureDesktop -ne 0) {
        New-Finding -Category 'UAC Config' -Severity 'Info' `
            -Title 'UAC configured sensibly' `
            -Evidence @{ EnableLUA=$enableLUA; ConsentPromptBehaviorAdmin=$consentAdmin; PromptOnSecureDesktop=$secureDesktop }
    }
}

function Invoke-ElevationContextCheck {
    $isAdmin = Test-IsAdministrator
    $il      = Get-ProcessIntegrityLevel

    if ($isAdmin -and $il -eq 'Medium') {
        New-Finding -Category 'Context' -Severity 'Medium' `
            -Title 'Admin user running at Medium IL' `
            -Detail 'Member of Administrators but not elevated. UAC bypass would be the path to High IL. Also: many checks below need elevation to be reliable.' `
            -Evidence @{ IsAdmin=$isAdmin; IntegrityLevel=$il }
    } else {
        New-Finding -Category 'Context' -Severity 'Info' `
            -Title 'Elevation context' `
            -Evidence @{ IsAdmin=$isAdmin; IntegrityLevel=$il }
    }

    if (-not $isAdmin) {
        New-Finding -Category 'Context' -Severity 'Info' `
            -Title 'Running without elevation — results may be incomplete' `
            -Detail 'Scheduled tasks, some services and HKLM reads may be partial. Re-run elevated for full coverage.'
    }
}

function Invoke-BypassArtifactCheck {
    # Hijack points are HKCU shell-command / env keys that known bypasses write.
    # A *normal* system does NOT have these user-level overrides, so their
    # presence is itself suspicious; a suspicious command string raises severity.
    $targets = @(
        @{ Technique='mscfile (eventvwr)';        Path='HKCU:\Software\Classes\mscfile\Shell\Open\command';     Value='(default)' }
        @{ Technique='ms-settings (fodhelper/computerdefaults)'; Path='HKCU:\Software\Classes\ms-settings\Shell\Open\command'; Value='(default)' }
        @{ Technique='ms-settings DelegateExecute'; Path='HKCU:\Software\Classes\ms-settings\Shell\Open\command'; Value='DelegateExecute' }
        @{ Technique='Folder (sdclt)';            Path='HKCU:\Software\Classes\Folder\shell\open\command';      Value='(default)' }
        @{ Technique='exefile (slui)';            Path='HKCU:\Software\Classes\exefile\Shell\Open\command';     Value='(default)' }
        @{ Technique='windir env (DiskCleanup)';        Path='HKCU:\Environment';                                     Value='windir' }
        @{ Technique='COR_ENABLE_PROFILING (.NET Profiler #39)'; Path='HKCU:\Environment';                              Value='COR_ENABLE_PROFILING' }
        @{ Technique='COR_PROFILER (.NET Profiler #39)';         Path='HKCU:\Environment';                              Value='COR_PROFILER' }
        @{ Technique='COR_PROFILER_PATH (.NET Profiler #39)';    Path='HKCU:\Environment';                              Value='COR_PROFILER_PATH' }
    )

    foreach ($t in $targets) {
        try {
            if (-not (Test-Path $t.Path)) { continue }
            $item = Get-ItemProperty -Path $t.Path -ErrorAction Stop
            $prop = $item.PSObject.Properties[$t.Value]
            if ($null -eq $prop) { continue }
            $data = [string]$prop.Value

            # windir normally resolves to C:\Windows; anything else is a classic hijack.
            # COR_* values should never exist in HKCU\Environment on a clean system.
            $looksHijacked =
                ($t.Value -eq 'windir' -and $data -and $data -notmatch '^[A-Za-z]:\\Windows\\?$') -or
                ($t.Value -like 'COR_*') -or
                ($t.Value -ne 'windir' -and $t.Value -notlike 'COR_*')

            if (-not $looksHijacked) { continue }

            $suspicious = $false
            foreach ($p in $SuspiciousCommandPatterns) {
                if ($data -match $p) { $suspicious = $true; break }
            }

            New-Finding -Category 'Bypass Artifact' `
                -Severity ($(if ($suspicious) { 'Critical' } else { 'High' })) `
                -Title "Hijack key present: $($t.Technique)" `
                -Detail "HKCU override exists where a clean system has none$(if($suspicious){'; command string matches a suspicious pattern'})." `
                -Evidence @{ Path=$t.Path; Value=$t.Value; Data=$data }
        } catch {
            New-Finding -Category 'Bypass Artifact' -Severity 'Info' `
                -Title "Error reading $($t.Path)" -Detail $_.Exception.Message
        }
    }
}

function Invoke-AutoElevateManifestCheck {
    # Correctly detect auto-elevate binaries by reading the embedded manifest,
    # NOT by inspecting .NET attributes. Scope to System32 and skip giant/
    # already-known-signed noise by only reporting the elevated set.
    $dir = Join-Path $env:WINDIR 'System32'
    $exes = Get-ChildItem -Path $dir -Filter '*.exe' -File -ErrorAction SilentlyContinue
    $count = 0
    foreach ($exe in $exes) {
        try {
            $manifest = Get-EmbeddedManifestText -Path $exe.FullName
            if ([string]::IsNullOrEmpty($manifest)) { continue }
            if ($manifest -match '<autoElevate>\s*true\s*</autoElevate>') {
                $count++
                # These are legitimate Windows auto-elevate binaries; list them so
                # the analyst can cross-check them against the hijack keys above.
                New-Finding -Category 'AutoElevate' -Severity 'Info' `
                    -Title "Auto-elevate binary: $($exe.Name)" `
                    -Detail 'Legitimate OS binary that auto-elevates; a candidate target for registry-hijack bypasses.' `
                    -Evidence @{ Path=$exe.FullName; Signed=(Test-FileMicrosoftSigned $exe.FullName) }
            }
        } catch { continue }
    }
    if ($count -eq 0) {
        New-Finding -Category 'AutoElevate' -Severity 'Info' `
            -Title 'No auto-elevate manifests found (or insufficient privileges to read)'
    }
}

function Invoke-ServiceCheck {
    # LocalSystem auto/manual services are an attack surface for privilege abuse.
    # Flag only those whose binary path is unquoted-with-spaces or non-system,
    # which is the condition that actually matters — not merely "runs as SYSTEM".
    try {
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            Where-Object { $_.StartName -eq 'LocalSystem' -and $_.StartMode -in @('Auto','Manual') }
    } catch {
        New-Finding -Category 'Services' -Severity 'Info' `
            -Title 'Cannot enumerate services' -Detail $_.Exception.Message
        return
    }

    foreach ($svc in $services) {
        $pathName = $svc.PathName
        if ([string]::IsNullOrWhiteSpace($pathName)) { continue }

        # Extract the executable path (handles quoted and unquoted).
        $exePath = if ($pathName -match '^\s*"([^"]+)"') { $matches[1] }
                   elseif ($pathName -match '^\s*(\S+\.exe)') { $matches[1] }
                   else { $pathName }

        $unquotedWithSpaces = ($pathName -notmatch '^\s*"') -and ($exePath -match '\s')

        if ($unquotedWithSpaces) {
            New-Finding -Category 'Services' -Severity 'High' `
                -Title "Unquoted service path: $($svc.Name)" `
                -Detail 'LocalSystem service with unquoted path containing spaces — classic privilege escalation vector.' `
                -Evidence @{ Service=$svc.Name; PathName=$pathName }
        }
    }
}

function Invoke-PhantomDllCheck {
    # Check whether DLLs that elevated binaries are known to probe are ABSENT
    # from System32 (phantom slot = available for planting), or PRESENT but
    # unsigned (active hijack indicator).
    #
    # Each entry: DLL name, which elevated binary loads it, known bypass technique.
    $phantomCandidates = @(
        @{ Dll='wow64log.dll';    Loader='64-bit elevated processes';      Technique='General WoW64 logging hook' }
        @{ Dll='oci.dll';         Loader='mmc.exe / comexp.msc';           Technique='ShaderCache junction bypass (SharpBypassUAC shadercache)' }
        @{ Dll='npmproxy.dll';    Loader='mmc.exe';                        Technique='MMC DLL side-loading' }
        @{ Dll='WLBSCTRL.dll';   Loader='svchost.exe (IKEEXT service)';   Technique='IKEEXT DLL hijack' }
        @{ Dll='wbemcomn.dll';    Loader='WMI provider host';              Technique='WMI provider DLL hijack' }
        @{ Dll='fveapi.dll';     Loader='Various elevated BitLocker procs'; Technique='BitLocker DLL hijack' }
        @{ Dll='TSMSISrv.dll';   Loader='mmc.exe';                        Technique='MMC snap-in DLL hijack' }
        @{ Dll='ntwdblib.dll';   Loader='Various management tools';        Technique='SQL client DLL hijack' }
    )

    # MSDT DLL hijack (#72): BluetoothDiagnosticUtil.dll in %LOCALAPPDATA%\Microsoft\WindowsApps
    $msdtDllPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\BluetoothDiagnosticUtil.dll'
    if (Test-Path $msdtDllPath) {
        $signed = Test-FileMicrosoftSigned $msdtDllPath
        New-Finding -Category 'DLL Hijack' -Severity $(if ($signed) { 'Medium' } else { 'Critical' }) `
            -Title "BluetoothDiagnosticUtil.dll found in WindowsApps" `
            -Detail "BluetoothDiagnosticUtil.dll exists in %LOCALAPPDATA%\Microsoft\WindowsApps. This file is used by the MSDT/sdiagnhost DLL hijack bypass (UACME #72). sdiagnhost.exe loads this DLL at high integrity when msdt.exe runs the Bluetooth diagnostic pack.$(if (-not $signed) { ' The file is NOT Microsoft-signed — strong indicator of active DLL hijack.' })" `
            -Evidence @{ Path=$msdtDllPath; Signed=$signed; Technique='MSDT sdiagnhost DLL hijack (UACME #72)' }
    }

    $sys32 = Join-Path $env:WINDIR 'System32'

    foreach ($entry in $phantomCandidates) {
        $dll  = $entry.Dll
        $full = Join-Path $sys32 $dll
        if (-not (Test-Path $full)) {
            New-Finding -Category 'DLL Hijack' -Severity 'Info' `
                -Title "Phantom DLL slot available: $dll" `
                -Detail "Absent from System32. Loaded by $($entry.Loader). Technique: $($entry.Technique). Not an active compromise, but an attacker with write access to System32 could plant a payload here." `
                -Evidence @{ ExpectedPath=$full; Loader=$entry.Loader; Technique=$entry.Technique }
        } else {
            # It exists — only interesting if it is NOT Microsoft-signed.
            if (-not (Test-FileMicrosoftSigned $full)) {
                New-Finding -Category 'DLL Hijack' -Severity 'Critical' `
                    -Title "Unsigned DLL in System32: $dll" `
                    -Detail "A normally-absent DLL exists and is not Microsoft-signed — strong indicator of a planted hijack DLL. Expected loader: $($entry.Loader). Known technique: $($entry.Technique)." `
                    -Evidence @{ Path=$full; Loader=$entry.Loader; Technique=$entry.Technique }
            }
        }
    }
}

function Invoke-ShaderCacheJunctionCheck {
    # Detect the Intel ShaderCache junction bypass: the attack replaces the
    # ShaderCache directory with an NTFS junction pointing to \??\GLOBALROOT\RPC CONTROL.
    # A legitimate ShaderCache is a normal directory, never a reparse point.
    $shaderCachePath = Join-Path $env:LOCALAPPDATA 'Low\Intel\ShaderCache'

    if (-not (Test-Path (Split-Path $shaderCachePath -Parent))) {
        # No Intel\ShaderCache parent — Intel GPU driver likely not installed.
        New-Finding -Category 'ShaderCache' -Severity 'Info' `
            -Title 'Intel ShaderCache directory not present' `
            -Detail 'Intel GPU driver does not appear to be installed. The ShaderCache junction bypass (shadercache) is not applicable on this host.'
        return
    }

    if (Test-Path $shaderCachePath) {
        $item = Get-Item -Path $shaderCachePath -Force -ErrorAction SilentlyContinue
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            # ShaderCache is a reparse point — this is NOT normal.
            $target = $null
            try {
                # fsutil reads the reparse point target without following it.
                $fsutil = & fsutil reparsepoint query $shaderCachePath 2>$null
                $target = ($fsutil | Select-String 'Substitute Name:' | Select-Object -First 1) -replace '.*Substitute Name:\s*', ''
            } catch {}

            $severity = 'Critical'
            $detail   = 'ShaderCache directory is a reparse point (junction/symlink). A legitimate Intel installation uses a normal directory. This is a strong indicator of the ShaderCache junction bypass.'
            if ($target -match 'RPC CONTROL|GLOBALROOT') {
                $detail += " Target points to '$target' — matches the known attack chain (junction → Object Manager namespace)."
            }

            New-Finding -Category 'ShaderCache' -Severity $severity `
                -Title 'ShaderCache directory is a reparse point (junction)' `
                -Detail $detail `
                -Evidence @{ Path=$shaderCachePath; ReparseTarget=$target }
        } else {
            New-Finding -Category 'ShaderCache' -Severity 'Info' `
                -Title 'ShaderCache directory is a normal directory' `
                -Detail 'No junction detected. Intel GPU driver ShaderCache appears legitimate.'
        }
    } else {
        # Directory absent but parent exists — could be post-attack cleanup.
        New-Finding -Category 'ShaderCache' -Severity 'Low' `
            -Title 'ShaderCache directory missing (parent exists)' `
            -Detail 'Intel driver parent directory exists but ShaderCache is absent. Could be normal, or could indicate post-attack cleanup. Check if Intel GPU driver is installed and functioning.'
    }
}

function Invoke-COMElevationCheck {
    # Audit COM classes that have autoElevate=true in their registration.
    # CMSTPLUA ({3E5FC7F9-9A51-4367-9063-A120244FBEC7}) is the primary target
    # for SharpBypassUAC's cmstp method, but we check the broader set.
    #
    # A finding here means: the COM class exists and can be elevated via moniker.
    # This is by design on a normal system — but if the InProcServer32/LocalServer32
    # binary is missing, unsigned, or not Microsoft-owned, that's suspicious.
    $knownElevatableCLSIDs = @(
        @{ CLSID='{3E5FC7F9-9A51-4367-9063-A120244FBEC7}'; Name='CMSTPLUA';                   Technique='SharpBypassUAC cmstp method' }
        @{ CLSID='{D2E7025F-2709-459E-8F70-3ABB3B2AF721}'; Name='ColorDataProxy';             Technique='UACME method 36' }
        @{ CLSID='{9BA05972-F6A8-11CF-A442-00A0C90A8F39}'; Name='ShellWindows';               Technique='UACME method 22' }
        @{ CLSID='{C090CEEA-B7E0-11D0-B775-00A0C906AF45}'; Name='CMSTPLuaUtil2';              Technique='Alternate CMSTPLUA interface' }
        @{ CLSID='{A6BFEA43-501F-456F-A845-983D3AD7B8F0}'; Name='VirtualFactoryServer';       Technique='SharpBypassUAC factoryserver (UACME #74)' }
        @{ CLSID='{12C21EA7-2EB8-4B55-9249-AC243DA8C666}'; Name='DiagCplFactoryServer';       Technique='SharpBypassUAC diagcpl (UACME #75)' }
    )

    foreach ($entry in $knownElevatableCLSIDs) {
        $clsidPath = "Registry::HKCR\CLSID\$($entry.CLSID)"
        if (-not (Test-Path $clsidPath)) { continue }

        try {
            $clsidProps = Get-ItemProperty -Path $clsidPath -ErrorAction Stop

            # Check Elevation sub-key for auto-elevate flag
            $elevPath = Join-Path $clsidPath 'Elevation'
            $autoElevate = $false
            if (Test-Path $elevPath) {
                $elevProps = Get-ItemProperty -Path $elevPath -ErrorAction SilentlyContinue
                $enabled = $elevProps.PSObject.Properties['Enabled']
                if ($enabled -and $enabled.Value -eq 1) { $autoElevate = $true }
            }

            # Find the server binary
            $serverBinary = $null
            foreach ($subkey in @('InProcServer32', 'LocalServer32')) {
                $serverPath = Join-Path $clsidPath $subkey
                if (Test-Path $serverPath) {
                    $serverProps = Get-ItemProperty -Path $serverPath -ErrorAction SilentlyContinue
                    $default = $serverProps.PSObject.Properties['(default)']
                    if ($default) { $serverBinary = $default.Value -replace '"', ''; break }
                }
            }

            if ($autoElevate) {
                $signed = $false
                if ($serverBinary -and (Test-Path $serverBinary)) {
                    $signed = Test-FileMicrosoftSigned $serverBinary
                }

                $severity = 'Info'
                $detail   = "COM class $($entry.Name) is registered with auto-elevate. Known technique: $($entry.Technique)."
                if ($serverBinary -and (Test-Path $serverBinary) -and -not $signed) {
                    $severity = 'Critical'
                    $detail  += ' The server binary is NOT Microsoft-signed — possible COM object hijack.'
                }

                New-Finding -Category 'COM Elevation' -Severity $severity `
                    -Title "Auto-elevate COM class: $($entry.Name) $($entry.CLSID)" `
                    -Detail $detail `
                    -Evidence @{ CLSID=$entry.CLSID; Name=$entry.Name; ServerBinary=$serverBinary; Signed=$signed; Technique=$entry.Technique }
            }
        } catch {
            continue
        }
    }
}

function Invoke-TokenImpersonationSurfaceCheck {
    # Assess exposure to token impersonation attacks:
    # - Is SeDebugPrivilege available? (required for OpenProcess on SYSTEM procs)
    # - Which sensitive processes are running? (winlogon, lsass = SYSTEM tokens)
    # - Is the current user a local admin? (precondition for token theft)

    # Check SeDebugPrivilege via whoami /priv (language-independent: parse privilege name)
    try {
        $privOutput = & whoami /priv 2>$null
        $hasDebug = $privOutput | Select-String 'SeDebugPrivilege'
        if ($hasDebug) {
            $enabled = $hasDebug -match 'Enabled'
            New-Finding -Category 'Token Surface' -Severity $(if ($enabled) { 'High' } else { 'Medium' }) `
                -Title "SeDebugPrivilege $(if ($enabled) { 'enabled' } else { 'available (disabled)' })" `
                -Detail "SeDebugPrivilege allows opening any process including SYSTEM-level. $(if ($enabled) { 'Currently ENABLED — token impersonation attack is possible right now.' } else { 'Currently disabled but available — can be enabled by the process.' }) This is the key privilege for SharpBypassUAC token impersonation (-t)." `
                -Evidence @{ Privilege='SeDebugPrivilege'; Status=$(if ($enabled) { 'Enabled' } else { 'Disabled' }) }
        }
    } catch {}

    # Enumerate sensitive processes that hold high-value tokens
    $sensitiveProcs = @(
        @{ Name='winlogon';  Identity='NT AUTHORITY\SYSTEM';         Risk='Primary SYSTEM token source for impersonation' }
        @{ Name='lsass';     Identity='NT AUTHORITY\SYSTEM';         Risk='SYSTEM token + credential material (high EDR alert)' }
        @{ Name='services';  Identity='NT AUTHORITY\SYSTEM';         Risk='Service Control Manager — SYSTEM token' }
        @{ Name='csrss';     Identity='NT AUTHORITY\SYSTEM';         Risk='Client/Server Runtime — protected process' }
        @{ Name='smss';      Identity='NT AUTHORITY\SYSTEM';         Risk='Session Manager — protected process' }
    )
    foreach ($proc in $sensitiveProcs) {
        try {
            $running = Get-Process -Name $proc.Name -ErrorAction SilentlyContinue
            if ($running) {
                New-Finding -Category 'Token Surface' -Severity 'Info' `
                    -Title "Token source available: $($proc.Name).exe (PID: $(($running | Select-Object -First 1).Id))" `
                    -Detail "$($proc.Risk). Runs as $($proc.Identity). SharpBypassUAC -t <pid> targets this process." `
                    -Evidence @{ Process=$proc.Name; PID=($running | Select-Object -First 1).Id; ExpectedIdentity=$proc.Identity }
            }
        } catch {}
    }
}

function Invoke-SysmonConfigCheck {
    # Verify that Sysmon is installed and configured to log the event types
    # needed to detect UAC bypass techniques. This is a posture check, not an
    # artifact check — it tells the analyst whether their monitoring is adequate.
    $sysmonService = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue
    if (-not $sysmonService) {
        New-Finding -Category 'Monitoring' -Severity 'High' `
            -Title 'Sysmon not installed' `
            -Detail 'Sysmon is not running on this host. Without Sysmon, detection of UAC bypass techniques relies solely on Windows Security event logs, which lack the granularity needed for: DLL load monitoring (Event 7), registry value set details (Event 13), reparse point creation (Event 11), and process access chains (Event 10).'
        return
    }

    $running = $sysmonService | Where-Object { $_.Status -eq 'Running' }
    if (-not $running) {
        New-Finding -Category 'Monitoring' -Severity 'High' `
            -Title 'Sysmon installed but not running' `
            -Detail "Sysmon service exists ($($sysmonService.Name)) but is not in Running state. No events are being logged." `
            -Evidence @{ ServiceName=$sysmonService.Name; Status=$sysmonService.Status }
        return
    }

    New-Finding -Category 'Monitoring' -Severity 'Info' `
        -Title "Sysmon is running ($($running.Name))" `
        -Detail 'Sysmon is active. Verify the configuration includes: Event 1 (Process Create — DLLHost.exe with factory CLSIDs, msdt.exe, mmc.exe eventvwr.msc, computerdefaults.exe), Event 5 (Process Terminate), Event 7 (Image Loaded — oci.dll, BluetoothDiagnosticUtil.dll), Event 10 (Process Access for token theft), Event 11 (File Create for reparse points), Event 12/13 (Registry Create/Value Set — HKCU hijack keys, COR_PROFILER env vars).' `
        -Evidence @{ ServiceName=$running.Name; Status='Running' }

    # Check for Sysmon config by looking at its driver's event log channel
    try {
        $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
        if (-not $sysmonLog.IsEnabled) {
            New-Finding -Category 'Monitoring' -Severity 'Medium' `
                -Title 'Sysmon event log channel is disabled' `
                -Detail 'The Sysmon log channel exists but is not enabled. Events are not being recorded.'
        }
    } catch {
        New-Finding -Category 'Monitoring' -Severity 'Medium' `
            -Title 'Cannot access Sysmon event log' `
            -Detail "Sysmon service is running but the event log channel could not be queried: $($_.Exception.Message)"
    }
}

function Invoke-EventLogArtifactScan {
    # Scan recent Sysmon and Security event logs for artifacts that indicate
    # a UAC bypass has already occurred. This is retrospective detection.
    # Limit to last 24 hours to keep runtime reasonable.
    $cutoff = (Get-Date).AddHours(-24)

    # --- Sysmon Event ID 13: Registry Value Set (bypass artifact keys) ---
    try {
        $regEvents = Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-Sysmon/Operational'; Id=13; StartTime=$cutoff
        } -MaxEvents 500 -ErrorAction Stop

        $suspiciousKeys = @(
            'ms-settings\\Shell\\Open\\command',
            'mscfile\\Shell\\Open\\command',
            'Folder\\shell\\open\\command',
            'exefile\\Shell\\Open\\command',
            'Environment\\windir'
        )

        foreach ($evt in $regEvents) {
            $msg = $evt.Message
            foreach ($key in $suspiciousKeys) {
                if ($msg -match [regex]::Escape($key)) {
                    New-Finding -Category 'Event Log Artifact' -Severity 'Critical' `
                        -Title "Sysmon: Registry hijack key written (Event 13)" `
                        -Detail "A Sysmon event recorded a write to a known bypass registry key matching '$key'. This may indicate an active or recent UAC bypass attempt." `
                        -Evidence @{ EventId=13; TimeCreated=$evt.TimeCreated.ToString('o'); Message=$msg.Substring(0, [Math]::Min(500, $msg.Length)) }
                    break
                }
            }
        }
    } catch {
        # Sysmon not available or no events — not an error for this check.
    }

    # --- Sysmon Event ID 11: File Create — oci.dll in System32 ---
    try {
        $fileEvents = Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-Sysmon/Operational'; Id=11; StartTime=$cutoff
        } -MaxEvents 500 -ErrorAction Stop

        foreach ($evt in $fileEvents) {
            $msg = $evt.Message
            if ($msg -match 'System32\\oci\.dll') {
                New-Finding -Category 'Event Log Artifact' -Severity 'Critical' `
                    -Title 'Sysmon: oci.dll created in System32 (Event 11)' `
                    -Detail 'oci.dll was written to System32. This file does not exist on a default Windows installation and is a known payload target for the Intel ShaderCache junction bypass.' `
                    -Evidence @{ EventId=11; TimeCreated=$evt.TimeCreated.ToString('o'); Message=$msg.Substring(0, [Math]::Min(500, $msg.Length)) }
            }
        }
    } catch {}

    # --- Sysmon Event ID 7: Image Loaded — oci.dll loaded by mmc.exe ---
    try {
        $loadEvents = Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-Sysmon/Operational'; Id=7; StartTime=$cutoff
        } -MaxEvents 500 -ErrorAction Stop

        foreach ($evt in $loadEvents) {
            $msg = $evt.Message
            if ($msg -match 'oci\.dll' -and $msg -match 'mmc\.exe') {
                New-Finding -Category 'Event Log Artifact' -Severity 'Critical' `
                    -Title 'Sysmon: oci.dll loaded by mmc.exe (Event 7)' `
                    -Detail 'mmc.exe loaded oci.dll — this combination is the final stage of the Intel ShaderCache junction bypass. The payload DLL has been executed with high integrity.' `
                    -Evidence @{ EventId=7; TimeCreated=$evt.TimeCreated.ToString('o'); Message=$msg.Substring(0, [Math]::Min(500, $msg.Length)) }
            }
        }
    } catch {}

    # --- Sysmon Event ID 5: Process Terminated — sihost/ShellHost killed ---
    try {
        $termEvents = Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-Sysmon/Operational'; Id=5; StartTime=$cutoff
        } -MaxEvents 500 -ErrorAction Stop

        $shellKills = $termEvents | Where-Object {
            $_.Message -match 'sihost\.exe|ShellHost\.exe'
        }
        if ($shellKills.Count -ge 2) {
            $times = ($shellKills | ForEach-Object { $_.TimeCreated.ToString('HH:mm:ss') }) -join ', '
            New-Finding -Category 'Event Log Artifact' -Severity 'High' `
                -Title "Sysmon: Shell processes terminated ($($shellKills.Count) events in 24h)" `
                -Detail "sihost.exe and/or ShellHost.exe were terminated $($shellKills.Count) times in the last 24 hours. This pattern matches the Intel ShaderCache junction bypass, which kills these processes to release handles on the ShaderCache directory." `
                -Evidence @{ EventId=5; Count=$shellKills.Count; Times=$times }
        }
    } catch {}

    # --- Sysmon Event ID 10: Process Access — token theft from sensitive procs ---
    try {
        $accessEvents = Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-Sysmon/Operational'; Id=10; StartTime=$cutoff
        } -MaxEvents 500 -ErrorAction Stop

        foreach ($evt in $accessEvents) {
            $msg = $evt.Message
            if ($msg -match '(winlogon|lsass)\.exe' -and $msg -match 'PROCESS_QUERY') {
                New-Finding -Category 'Event Log Artifact' -Severity 'High' `
                    -Title 'Sysmon: Process access to sensitive SYSTEM process (Event 10)' `
                    -Detail 'A process accessed winlogon.exe or lsass.exe with query rights. This pattern matches token impersonation techniques (OpenProcess → OpenProcessToken → DuplicateTokenEx chain).' `
                    -Evidence @{ EventId=10; TimeCreated=$evt.TimeCreated.ToString('o'); Message=$msg.Substring(0, [Math]::Min(500, $msg.Length)) }
            }
        }
    } catch {}

    # --- Sysmon Event ID 13: COR_PROFILER registry writes (.NET Profiler #39) ---
    try {
        if ($regEvents) {
            foreach ($evt in $regEvents) {
                $msg = $evt.Message
                if ($msg -match 'COR_ENABLE_PROFILING|COR_PROFILER|COR_PROFILER_PATH') {
                    New-Finding -Category 'Event Log Artifact' -Severity 'Critical' `
                        -Title 'Sysmon: .NET Profiler env var set in registry (Event 13)' `
                        -Detail "COR_PROFILER environment variable written to HKCU\\Environment. This is the primary indicator of the .NET CLR Profiler bypass (UACME #39). The CLR will load the attacker's DLL as a profiler in any .NET process." `
                        -Evidence @{ EventId=13; TimeCreated=$evt.TimeCreated.ToString('o'); Message=$msg.Substring(0, [Math]::Min(500, $msg.Length)) }
                    break
                }
            }
        }
    } catch {}

    # --- Sysmon Event ID 1: Process Create — DLLHost.exe with factory CLSIDs (#74, #75) ---
    try {
        $procEvents = Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$cutoff
        } -MaxEvents 1000 -ErrorAction Stop

        foreach ($evt in $procEvents) {
            $msg = $evt.Message
            # IElevatedFactoryServer CLSIDs used by #74 and #75
            if ($msg -match 'dllhost\.exe' -and ($msg -match 'A6BFEA43-501F-456F-A845-983D3AD7B8F0' -or $msg -match '12C21EA7-2EB8-4B55-9249-AC243DA8C666')) {
                $technique = if ($msg -match 'A6BFEA43') { 'ElevatedFactoryServer (UACME #74)' } else { 'DiagCpl factory (UACME #75)' }
                New-Finding -Category 'Event Log Artifact' -Severity 'Critical' `
                    -Title "Sysmon: DLLHost.exe with factory server CLSID (Event 1)" `
                    -Detail "DLLHost.exe spawned with /Processid matching $technique. This indicates a two-step COM elevation bypass via IElevatedFactoryServer → ICMLuaUtil chain." `
                    -Evidence @{ EventId=1; TimeCreated=$evt.TimeCreated.ToString('o'); Technique=$technique; Message=$msg.Substring(0, [Math]::Min(500, $msg.Length)) }
            }

            # ALPC debug object bypass (#59): elevated computerdefaults.exe or winver.exe spawned
            if ($msg -match 'computerdefaults\.exe' -and $msg -match 'High') {
                New-Finding -Category 'Event Log Artifact' -Severity 'High' `
                    -Title 'Sysmon: computerdefaults.exe at high integrity (Event 1)' `
                    -Detail 'computerdefaults.exe running at high integrity level. This process is used by the ALPC debug object bypass (UACME #59) as the elevated target whose handle is captured via debug object manipulation.' `
                    -Evidence @{ EventId=1; TimeCreated=$evt.TimeCreated.ToString('o'); Message=$msg.Substring(0, [Math]::Min(500, $msg.Length)) }
            }

            # MSDT DLL hijack (#72): msdt.exe with BluetoothDiagnostic
            if ($msg -match 'msdt\.exe' -and $msg -match 'BluetoothDiagnostic') {
                New-Finding -Category 'Event Log Artifact' -Severity 'Critical' `
                    -Title 'Sysmon: msdt.exe with BluetoothDiagnostic pack (Event 1)' `
                    -Detail 'msdt.exe launched with Bluetooth diagnostic pack arguments. This is the trigger for the MSDT/sdiagnhost DLL hijack bypass (UACME #72), which causes sdiagnhost.exe to load a hijacked BluetoothDiagnosticUtil.dll at high integrity.' `
                    -Evidence @{ EventId=1; TimeCreated=$evt.TimeCreated.ToString('o'); Message=$msg.Substring(0, [Math]::Min(500, $msg.Length)) }
            }

            # .NET Profiler (#39): mmc.exe eventvwr.msc with COR_PROFILER set
            if ($msg -match 'mmc\.exe' -and $msg -match 'eventvwr\.msc') {
                New-Finding -Category 'Event Log Artifact' -Severity 'Medium' `
                    -Title 'Sysmon: mmc.exe eventvwr.msc launched (Event 1)' `
                    -Detail 'mmc.exe launched with eventvwr.msc snap-in. This is a common trigger for the .NET Profiler bypass (UACME #39). Cross-reference with COR_PROFILER registry writes to confirm exploitation.' `
                    -Evidence @{ EventId=1; TimeCreated=$evt.TimeCreated.ToString('o'); Message=$msg.Substring(0, [Math]::Min(500, $msg.Length)) }
            }
        }
    } catch {}

    # --- Sysmon Event ID 7: Image Loaded — BluetoothDiagnosticUtil.dll loaded by sdiagnhost (#72) ---
    try {
        if ($loadEvents) {
            foreach ($evt in $loadEvents) {
                $msg = $evt.Message
                if ($msg -match 'BluetoothDiagnosticUtil\.dll' -and $msg -match 'sdiagnhost\.exe') {
                    New-Finding -Category 'Event Log Artifact' -Severity 'Critical' `
                        -Title 'Sysmon: BluetoothDiagnosticUtil.dll loaded by sdiagnhost (Event 7)' `
                        -Detail 'sdiagnhost.exe loaded BluetoothDiagnosticUtil.dll — this is the execution stage of the MSDT DLL hijack bypass (UACME #72). The payload DLL has been executed at high integrity.' `
                        -Evidence @{ EventId=7; TimeCreated=$evt.TimeCreated.ToString('o'); Message=$msg.Substring(0, [Math]::Min(500, $msg.Length)) }
                }
            }
        }
    } catch {}
}

function Invoke-ReparsePointScan {
    # Scan known directories for unexpected NTFS reparse points (junctions/symlinks).
    # Reparse points are used by the ShaderCache bypass and other file-system-based
    # attacks. Legitimate junctions exist (e.g., Documents and Settings → Users)
    # but junctions in application data directories are suspicious.
    $scanPaths = @(
        @{ Path=(Join-Path $env:LOCALAPPDATA 'Low\Intel');              Context='Intel ShaderCache bypass target' }
        @{ Path=(Join-Path $env:LOCALAPPDATA 'Low');                    Context='Low-integrity app data (general)' }
        @{ Path=(Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'); Context='MSDT DLL hijack target (UACME #72)' }
    )

    foreach ($scan in $scanPaths) {
        if (-not (Test-Path $scan.Path)) { continue }
        try {
            $reparseItems = Get-ChildItem -Path $scan.Path -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint }

            foreach ($rp in $reparseItems) {
                $target = $null
                try {
                    $fsutil = & fsutil reparsepoint query $rp.FullName 2>$null
                    $target = ($fsutil | Select-String 'Substitute Name:' | Select-Object -First 1) -replace '.*Substitute Name:\s*', ''
                } catch {}

                $severity = 'Medium'
                if ($target -match 'RPC CONTROL|GLOBALROOT') { $severity = 'Critical' }

                New-Finding -Category 'Reparse Point' -Severity $severity `
                    -Title "Reparse point found: $($rp.Name) in $($scan.Path)" `
                    -Detail "Context: $($scan.Context). Reparse points in application data directories are unusual and may indicate junction-based file system attacks." `
                    -Evidence @{ Path=$rp.FullName; Target=$target; Context=$scan.Context }
            }
        } catch {}
    }
}

function Invoke-HighPrivTaskCheck {
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.Principal.RunLevel -eq 'Highest' }
    } catch {
        New-Finding -Category 'Scheduled Tasks' -Severity 'Info' `
            -Title 'Cannot enumerate scheduled tasks' -Detail $_.Exception.Message
        return
    }
    foreach ($t in $tasks) {
        New-Finding -Category 'Scheduled Tasks' -Severity 'Info' `
            -Title "Highest-privilege task: $($t.TaskName)" `
            -Detail 'Runs with highest privileges; review the action/trigger and the principal for abuse potential.' `
            -Evidence @{ TaskPath=$t.TaskPath; TaskName=$t.TaskName; UserId=$t.Principal.UserId }
    }
}

#endregion Checks ---------------------------------------------------------------

#region Main --------------------------------------------------------------------

# Phase 1: Host posture
Invoke-ElevationContextCheck
Invoke-UACLevelCheck
Invoke-SysmonConfigCheck

# Phase 2: Static artifacts (registry, file system, DLL)
Invoke-BypassArtifactCheck
Invoke-ShaderCacheJunctionCheck
Invoke-PhantomDllCheck
Invoke-ReparsePointScan

# Phase 3: Attack surface analysis
Invoke-AutoElevateManifestCheck
Invoke-COMElevationCheck
Invoke-TokenImpersonationSurfaceCheck
Invoke-ServiceCheck
Invoke-HighPrivTaskCheck

# Phase 4: Historical event log scanning
Invoke-EventLogArtifactScan

if ($AsJson) {
    $script:Findings | ConvertTo-Json -Depth 6
} else {
    $order = @{ Critical=0; High=1; Medium=2; Low=3; Info=4 }
    $script:Findings |
        Sort-Object { $order[$_.Severity] }, Category |
        Format-Table Severity, Category, Title -AutoSize -Wrap

    $summary = $script:Findings | Group-Object Severity |
        Sort-Object { $order[$_.Name] } |
        ForEach-Object { "$($_.Name): $($_.Count)" }
    Write-Host ""
    Write-Host ("Summary -> " + ($summary -join '  |  '))
}

#endregion Main -----------------------------------------------------------------
