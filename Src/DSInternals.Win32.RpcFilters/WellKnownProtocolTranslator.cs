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
    public static readonly Guid RRP_NP = new("894DE0C0-0D55-11D3-A322-00C04FA321A1");

    /// <summary>
    /// MS-RSP: Remote Shutdown Protocol (WindowsShutdown)
    /// </summary>
    public static readonly Guid RRP_TCP = new("D95AFE70-A6D5-4259-822E-2C84DA1DDB0D");

    /// <summary>
    /// MS-RPRN: Print Spooler Remote Protocol
    /// </summary>
    public static readonly Guid RPRN = new("12345678-1234-ABCD-EF00-0123456789AB");

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
    // TODO: Add support for more protocols

    /// <summary>
    /// Translates a well-known RPC protocol to its corresponding interface UUID.
    /// </summary>
    /// <param name="protocol">RPC protocol enumeration</param>
    /// <returns>Interface UUID</returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    public static Guid Translate(this WellKnownProtocol protocol)
    {
        return protocol switch
        {
            WellKnownProtocol.DirectoryReplication => DRSR,
            WellKnownProtocol.ServiceControl => SCMR,
            WellKnownProtocol.TaskSchedulerAgent => SASec,
            WellKnownProtocol.NetSchedule => ATSvc,
            WellKnownProtocol.TaskSchedulerService => TSCH,
            WellKnownProtocol.EventLog => EVEN,
            WellKnownProtocol.EventLogV6 => EVEN6,
            WellKnownProtocol.MimiCom => KIWI,
            WellKnownProtocol.Registry => RRP,
            WellKnownProtocol.InitShutdown => RRP_NP,
            WellKnownProtocol.WindowsShutdown => RRP_TCP,
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
            _ => throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "This protocol is not yet supported.")
        };
    }

    /// <summary>
    /// Translates a well-known RPC operation to its corresponding interface UUID and operation number.
    /// </summary>
    /// <param name="operation">RPC protocol operation enumeration</param>
    /// <returns>Interface UUID and operation number</returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    public static (Guid InterfaceUUID, ushort OperationNumber) Translate(this WellKnownOperation operation)
    {
        return operation switch
        {
            WellKnownOperation.IDL_DRSGetNCChanges => (DRSR, 3),
            WellKnownOperation.EvtRpcClearLog => (EVEN6, 6),
            WellKnownOperation.ElfrClearELFW => (EVEN, 0),
            WellKnownOperation.ElfrClearELFA => (EVEN, 12),
            WellKnownOperation.RCreateServiceW => (SCMR, 12),
            _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, "This operation is not yet supported.")
        };
    }
}
