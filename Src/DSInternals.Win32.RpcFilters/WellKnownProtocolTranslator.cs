namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Well-known RPC protocol translator.
/// </summary>
public static class WellKnownProtocolTranslator
{
    /// <summary>
    /// MS-DRSR: Directory Replication Service Remote Protocol
    /// </summary>
    public static readonly Guid DRSR = new("e3514235-4b06-11d1-ab04-00c04fc2dcd2");

    /// <summary>
    /// MS-SCMR: Service Control Manager Remote Protocol
    /// </summary>
    public static readonly Guid SCMR = new("367ABB81-9844-35F1-AD32-98F038001003");

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (ITaskSchedulerService)
    /// </summary>
    public static readonly Guid TSCH = new("86D35949-83C9-4044-B424-DB363231FD0C");

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (ATSvc)
    /// </summary>
    public static readonly Guid ATSvc = new("1FF70682-0A51-30E8-076D-740BE8CEE98B");

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (SASec)
    /// </summary>
    public static readonly Guid SASec = new("378E52B0-C0A9-11CF-822D-00AA0051E40F");

    /// <summary>
    /// MS-EVEN: EventLog Remoting Protocol
    /// </summary>
    public static readonly Guid EVEN = new("82273FDC-E32A-18C3-3F78-827929DC23EA");

    /// <summary>
    /// MS-EVEN6: EventLog Remoting Protocol Version 6.0
    /// </summary>
    public static readonly Guid EVEN6 = new("F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C");

    /// <summary>
    /// MimiCom: Mimikatz Remote Protocol
    /// </summary>
    public static readonly Guid KIWI = new("17FC11E9-C258-4B8D-8D07-2F4125156244");

    /// <summary>
    /// MS-RRP: Windows Remote Registry Protocol
    /// </summary>
    public static readonly Guid RRP = new("338CD001-2244-31F1-AAAA-900038001003");

    /// <summary>
    /// MS-RSP: Remote Shutdown Protocol (InitShutdown)
    /// </summary>
    public static readonly Guid RSP_NP = new("894DE0C0-0D55-11D3-A322-00C04FA321A1");

    /// <summary>
    /// MS-RSP: Remote Shutdown Protocol (WindowsShutdown)
    /// </summary>
    public static readonly Guid RSP_TCP = new("D95AFE70-A6D5-4259-822E-2C84DA1DDB0D");

    /// <summary>
    /// MS-RPRN: Print Spooler Remote Protocol
    /// </summary>
    public static readonly Guid RPRN = new("12345678-1234-ABCD-EF00-0123456789AB");

    /// <summary>
    /// MS-PAR: Print System Asynchronous Remote Protocol
    /// </summary>
    public static readonly Guid PAR = new("76F03F96-CDFD-44fc-A22C-64950A001209");

    /// <summary>
    /// MS-DFS: Distributed File System Namespace Management Protocol
    /// </summary>
    public static readonly Guid DFSNM = new("4FC742E0-4A10-11CF-8273-00AA004AE673");

    /// <summary>
    /// MS-SAMR: Security Account Manager (SAM) Remote Protocol
    /// </summary>
    public static readonly Guid SAMR = new("12345778-1234-ABCD-EF00-0123456789AC");

    /// <summary>
    /// MS-NRPC: Netlogon Remote Protocol
    /// </summary>
    public static readonly Guid NRPC = new ("12345678-1234-ABCD-EF00-01234567CFFB");

    /// <summary>
    /// MS-FRS1: File Replication Service Remote Protocol
    /// </summary>
    public static readonly Guid FRS1 = new ("F5CC59B4-4264-101A-8C59-08002B2F8426");

    /// <summary>
    /// MS-FRS2: Distributed File System Replication Protocol
    /// </summary>
    public static readonly Guid FRS2 = new("897e2e5f-93f3-4376-9c9c-fd2277495c27");

    /// <summary>
    /// MS-FSRVP: Volume Shadow Copy Service Remote Protocol
    /// </summary>
    public static readonly Guid FSRVP = new ("a8e0653c-2744-4389-a61d-7373df8b2292");

    /// <summary>
    /// MS-EFSR: Encrypting File System Remote Protocol (EFSRPC)
    /// </summary>
    public static readonly Guid EFSR = new ("df1941c5-fe89-4e79-bf10-463657acf44d");

    /// <summary>
    /// MS-EFSR: Encrypting File System Remote Protocol (LSARPC)
    /// </summary>
    public static readonly Guid EFSR_LSA = new ("c681d488-d850-11d0-8c52-00c04fd90f7e");

    /// <summary>
    /// MS-SRVSVC: Server Service Remote Protocol
    /// </summary>
    public static readonly Guid SRVSVC = new ("4B324FC8-1670-01D3-1278-5A47BF6EE188");

    /// <summary>
    /// MS-WKSSVC: Workstation Service Remote Protocol
    /// </summary>
    public static readonly Guid WKSSVC = new ("6BFFD098-A112-3610-9833-46C3F87E345A");

    /// <summary>
    /// MS-BKRP: Backup Key Remote Protocol
    /// </summary>
    public static readonly Guid BKRP = new("3dde7c30-165d-11d1-ab8f-00805f14db40");

    /// <summary>
    /// MS-LSAD: Local Security Authority (LSA) Remote Protocol
    /// </summary>
    public static readonly Guid LSAD = new("12345778-1234-ABCD-EF00-0123456789AB");

    /// <summary>
    /// MS-DNSP: Domain Name Service (DNS) Server Management Protocol
    /// </summary>
    public static readonly Guid DNSP = new("50abc2a4-574d-40b3-9d66-ee4fd5fba076");

    /// <summary>
    /// MS-CSRA: Certificate Services Remote Administration Protocol (ICertAdminD)
    /// </summary>
    public static readonly Guid CSRA_ICertAdminD =  new("d99e6e71-fc88-11d0-b498-00a0c90312f3");

    /// <summary>
    /// MS-CSRA: Certificate Services Remote Administration Protocol (ICertAdminD2)
    /// </summary>
    public static readonly Guid CSRA_ICertAdminD2 = new("7fe0d935-dda6-443f-85d0-1cfb58fe41dd");

    /// <summary>
    /// MS-ICPR: ICertPassage Remote Protocol
    /// </summary>
    public static readonly Guid ICPR = new("91ae6020-9e3c-11cf-8d7c-00aa00c091be");

    /// <summary>
    /// MS-PAN: Print System Asynchronous Notification Protocol (IRPCAsyncNotify)
    /// </summary>
    public static readonly Guid PAN_IRPCAsyncNotify = new("0b6edbfa-4a24-4fc6-8a23-942b1eca65d1");

    /// <summary>
    /// MS-PAN: Print System Asynchronous Notification Protocol (IRPCRemoteObject)
    /// </summary>
    public static readonly Guid PAN_IRPCRemoteObject = new("ae33069b-a2a8-46ee-a235-ddfd339be281");

    /// <summary>
    /// MS-DRSR: IDL_DRSGetNCChanges
    /// </summary>
    public const ushort IDL_DRSGetNCChanges = 3;

    /// <summary>
    /// MS-EVEN6: EvtRpcClearLog
    /// </summary>
    public const ushort EvtRpcClearLog = 6;

    /// <summary>
    /// MS-EVEN: ElfrClearELFW
    /// </summary>
    public const ushort ElfrClearELFW = 0;

    /// <summary>
    /// MS-EVEN: ElfrClearELFA
    /// </summary>
    public const ushort ElfrClearELFA = 12;

    /// <summary>
    /// MS-SCMR: RCreateServiceW
    /// </summary>
    public const ushort RCreateServiceW = 12;

    /// <summary>
    /// MS-SCMR: RCreateWowService
    /// </summary>
    public const ushort RCreateWowService = 60;


    /// <summary>
    /// MS-DRSR: IDL_DRSReplicaAdd
    /// </summary>
    public const ushort IDL_DRSReplicaAdd = 5;

    /// <summary>
    /// MS-RRP: BaseRegCreateKey
    /// </summary>
    public const ushort BaseRegCreateKey = 6;

    /// <summary>
    /// MS-RRP: BaseRegSetValue
    /// </summary>
    public const ushort BaseRegSetValue = 22;

    /// <summary>
    /// MS-TSCH: SchRpcRegisterTask
    /// </summary>
    public const ushort SchRpcRegisterTask = 1;

    /// <summary>
    /// MS-TSCH: NetrJobAdd
    /// </summary>
    public const ushort NetrJobAdd = 0;

    /// <summary>
    /// MS-SRVS: NetrFileEnum
    /// </summary>
    public const ushort NetrFileEnum = 9;

    /// <summary>
    /// MS-SRVS: NetrSessionEnum
    /// </summary>
    public const ushort NetrSessionEnum = 12;

    /// <summary>
    /// MS-SRVS: NetrShareEnum
    /// </summary>
    public const ushort NetrShareEnum = 15;

    /// <summary>
    /// MS-SRVS: NetrConnectionEnum
    /// </summary>
    public const ushort NetrConnectionEnum = 8;

    /// <summary>
    /// MS-PAR: RpcAsyncAddPrinterDriver
    /// </summary>
    public const ushort RpcAsyncAddPrinterDriver = 39;

    /// <summary>
    /// MS-RPRN: RpcAddPrinterDriverEx
    /// </summary>
    public const ushort RpcAddPrinterDriverEx = 89;

    /// <summary>
    /// MS-RPRN: RpcRemoteFindFirstPrinterChangeNotification
    /// </summary>
    public const ushort RpcRemoteFindFirstPrinterChangeNotification = 62;

    /// <summary>
    /// MS-RPRN: RpcRemoteFindFirstPrinterChangeNotification
    /// </summary>
    public const ushort RpcRemoteFindFirstPrinterChangeNotificationEx = 65;

    /// <summary>
    /// MS-SAMR: SamrEnumerateGroupsInDomain
    /// </summary>
    public const ushort SamrEnumerateGroupsInDomain = 11;

    /// <summary>
    /// MS-SAMR: SamrEnumerateUsersInDomain
    /// </summary>
    public const ushort SamrEnumerateUsersInDomain = 13;

    /// <summary>
    /// MS-LSAD: LsarRetrievePrivateData
    /// </summary>
    public const ushort LsarRetrievePrivateData = 43;


    /// <summary>
    /// Translates a well-known RPC protocol to its corresponding interface UUID.
    /// </summary>
    /// <param name="protocol">RPC protocol enumeration</param>
    /// <returns>Interface UUID</returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    public static Guid ToInterfaceUUID(this WellKnownProtocol protocol)
    {
        return protocol switch
        {
            WellKnownProtocol.DirectoryReplicationService => DRSR,
            WellKnownProtocol.ServiceControlManager => SCMR,
            WellKnownProtocol.TaskSchedulerAgent => SASec,
            WellKnownProtocol.NetSchedule => ATSvc,
            WellKnownProtocol.TaskSchedulerService => TSCH,
            WellKnownProtocol.EventLog => EVEN,
            WellKnownProtocol.EventLogV6 => EVEN6,
            WellKnownProtocol.MimiCom => KIWI,
            WellKnownProtocol.RemoteRegistry => RRP,
            WellKnownProtocol.InitShutdown => RSP_NP,
            WellKnownProtocol.WindowsShutdown => RSP_TCP,
            WellKnownProtocol.SecurityAccountManager => SAMR,
            WellKnownProtocol.PrintSpooler => RPRN,
            WellKnownProtocol.NamespaceManagement => DFSNM,
            WellKnownProtocol.FileReplication => FRS1,
            WellKnownProtocol.DistributedFileReplication => FRS2,
            WellKnownProtocol.VolumeShadowCopy => FSRVP,
            WellKnownProtocol.Netlogon => NRPC,
            WellKnownProtocol.EncryptingFileSystem => EFSR,
            WellKnownProtocol.EncryptingFileSystemLSA => EFSR_LSA,
            WellKnownProtocol.ServerService => SRVSVC,
            WellKnownProtocol.WorkstationService => WKSSVC,
            WellKnownProtocol.BackupKey => BKRP,
            WellKnownProtocol.LocalSecurityAuthority => LSAD,
            WellKnownProtocol.DnsManagement => DNSP,
            _ => throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "This protocol is not yet supported.")
        };
    }

    /// <summary>
    /// Translates a well-known RPC operation to its corresponding interface UUID and operation number.
    /// </summary>
    /// <param name="operation">RPC protocol operation enumeration</param>
    /// <returns>Interface UUID and operation number</returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    public static (Guid InterfaceUUID, ushort OperationNumber) ToOperationNumber(this WellKnownOperation operation)
    {
        return operation switch
        {
            WellKnownOperation.IDL_DRSGetNCChanges => (DRSR, IDL_DRSGetNCChanges),
            WellKnownOperation.EvtRpcClearLog => (EVEN6, EvtRpcClearLog),
            WellKnownOperation.ElfrClearELFW => (EVEN, ElfrClearELFW),
            WellKnownOperation.ElfrClearELFA => (EVEN, ElfrClearELFA),
            WellKnownOperation.RCreateServiceW => (SCMR, RCreateServiceW),
            _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, "This operation is not yet supported.")
        };
    }

    /// <summary>
    /// Translates a well-known RPC interface UUID to its corresponding protocol name.
    /// </summary>
    /// <param name="interfaceUUID">RPC interface UUID</param>
    /// <returns>Protocol name</returns>
    public static string? ToProtocolName(this Guid? interfaceUUID)
    {
        if(interfaceUUID == null)
        {
            // No interface UUID is configured in the filter
            return null;
        }

        return interfaceUUID switch
        {
            { } when interfaceUUID == DRSR =>     "MS-DRSR",
            { } when interfaceUUID == SCMR =>     "MS-SCMR",
            { } when interfaceUUID == SASec =>    "MS-TSCH (SASec)",
            { } when interfaceUUID == ATSvc =>    "MS-TSCH (ATSvc)",
            { } when interfaceUUID == TSCH =>     "MS-TSCH (ITaskSchedulerService)",
            { } when interfaceUUID == EVEN =>     "MS-EVEN",
            { } when interfaceUUID == EVEN6 =>    "MS-EVEN6",
            { } when interfaceUUID == KIWI =>     "MimiCom",
            { } when interfaceUUID == RRP =>      "MS-RRP",
            { } when interfaceUUID == RSP_NP =>   "MS-RSP (InitShutdown)",
            { } when interfaceUUID == RSP_TCP =>  "MS-RSP (WindowsShutdown)",
            { } when interfaceUUID == RPRN =>     "MS-RPRN",
            { } when interfaceUUID == PAR =>      "MS-PAR",
            { } when interfaceUUID == DFSNM =>    "MS-DFSNM",
            { } when interfaceUUID == FRS1 =>     "MS-FRS1",
            { } when interfaceUUID == FRS2 =>     "MS-FRS2",
            { } when interfaceUUID == FSRVP =>    "MS-FSRP",
            { } when interfaceUUID == NRPC =>     "MS-NRPC",
            { } when interfaceUUID == EFSR =>     "MS-EFSR (\\pipe\\efsrpc)",
            { } when interfaceUUID == EFSR_LSA => "MS-EFSR (\\pipe\\lsarpc)",
            { } when interfaceUUID == SRVSVC =>   "MS-SRVSVC",
            { } when interfaceUUID == WKSSVC =>   "MS-WKSSVC",
            { } when interfaceUUID == BKRP =>     "MS-BKRP",
            { } when interfaceUUID == DNSP =>     "MS-DNSP",
            { } when interfaceUUID == SAMR =>     "MS-SAMR",
            // Return the original GUID if no match is found
            _ => interfaceUUID.ToString()
        };
    }

    /// <summary>
    /// Translates a well-known RPC operation number to its name.
    /// </summary>
    /// <param name="interfaceUUID">RPC interface UUID</param>
    /// <param name="operationNumber">Interface-specific operation number</param>
    /// <returns>Operation name</returns>
    public static string? ToOperationName(Guid? interfaceUUID, ushort? operationNumber)
    {
        if(operationNumber == null)
        {
            // No operation number is configured in the filter
            return null;
        }
        else if(interfaceUUID == null)
        {
            // Although the operation number is defined, it cannot be translated without the corresponding interface UUID
            return operationNumber.ToString();
        }

        // Both interface UUID and operation number are configured in the filter
        string? operationName = (interfaceUUID, operationNumber) switch
        {
            { } when interfaceUUID == DRSR && operationNumber == IDL_DRSGetNCChanges => nameof(IDL_DRSGetNCChanges),
            { } when interfaceUUID == EVEN6 && operationNumber == EvtRpcClearLog => nameof(EvtRpcClearLog),
            { } when interfaceUUID == EVEN && operationNumber == ElfrClearELFW => nameof(ElfrClearELFW),
            { } when interfaceUUID == EVEN && operationNumber == ElfrClearELFA => nameof(ElfrClearELFA),
            { } when interfaceUUID == SCMR && operationNumber == RCreateServiceW => nameof(RCreateServiceW),
            _ => null
        };

        if (operationName != null)
        {
            // Return the operation name and number if a match is found
            return $"{operationName} ({operationNumber})";
        }
        else
        {
            // Return the original operation number if no match is found
            return operationNumber.ToString();
        }
    }
}
