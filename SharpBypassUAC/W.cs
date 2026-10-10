using System;
using System.Text;
using System.Runtime.InteropServices;

namespace SharpBypassUAC
{
    /// <summary>
    /// D/Invoke helper: runtime API resolution via LoadLibrary + GetProcAddress.
    /// Avoids static P/Invoke declarations for sensitive Win32 APIs.
    /// Only kernel32 LoadLibrary/GetProcAddress are statically imported (bootstrap).
    /// </summary>
    public class W
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        /// <summary>Load a DLL module (LoadLibraryA wrapper).</summary>
        public static IntPtr M0(string dll)
        {
            IntPtr h = LoadLibrary(dll);
            if (h == IntPtr.Zero)
                throw new Exception("M0 failed: " + Marshal.GetLastWin32Error());
            return h;
        }

        /// <summary>Resolve a function address (GetProcAddress wrapper).</summary>
        public static IntPtr M1(IntPtr hModule, string proc)
        {
            IntPtr addr = GetProcAddress(hModule, proc);
            if (addr == IntPtr.Zero)
                throw new Exception("M1 failed: " + proc);
            return addr;
        }

        /// <summary>
        /// Resolve a Win32 function and return it as a typed delegate.
        /// Usage: var func = W.G&lt;MyDelegate&gt;("module.dll", "FunctionName");
        /// </summary>
        public static T G<T>(string dll, string proc) where T : class
        {
            IntPtr hModule = M0(dll);
            IntPtr addr = M1(hModule, proc);
            return (T)(object)Marshal.GetDelegateForFunctionPointer(addr, typeof(T));
        }

        /// <summary>XOR decode a byte array to string.</summary>
        public static string X(byte[] data, byte key)
        {
            byte[] decoded = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                decoded[i] = (byte)(data[i] ^ key);
            return Encoding.ASCII.GetString(decoded);
        }
    }
}
