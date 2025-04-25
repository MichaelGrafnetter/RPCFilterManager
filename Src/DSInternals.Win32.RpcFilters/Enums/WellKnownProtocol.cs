namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Well-known RPC protocols.
/// </summary>
public enum WellKnownProtocol
{
    /// <summary>
    /// MS-DRSR: Directory Replication Service Remote Protocol
    /// </summary>
    DirectoryReplication,

    /// <summary>
    /// MS-SCMR: Service Control Manager Remote Protocol
    /// </summary>
    ServiceControl,

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (SASec)
    /// </summary>
    TaskSchedulerAgent,

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (ATSvc)
    /// </summary>
    NetSchedule,

    /// <summary>
    /// MS-TSCH: Task Scheduler Service Remoting Protocol (ITaskSchedulerService)
    /// </summary>
    TaskSchedulerService,

    /// <summary>
    /// MS-EVEN: EventLog Remoting Protocol
    /// </summary>
    EventLog,

    /// <summary>
    /// MS-EVEN6: EventLog Remoting Protocol Version 6.0
    /// </summary>
    EventLogV6,

    /// <summary>
    /// MimiCom: Mimikatz Remote Protocol
    /// </summary>
    MimiCom,

    /// <summary>
    /// MS-RRP: Windows Remote Registry Protocol
    /// </summary>
    Registry,

    /// <summary>
    /// MS-RSP: Remote Shutdown Protocol
    /// </summary>
    InitShutdown,

    /// <summary>
    /// MS-RSP: Remote Shutdown Protocol
    /// </summary>
    WindowsShutdown,

    /// <summary>
    /// MS-SAMR: Security Account Manager (SAM) Remote Protocol
    /// </summary>
    SecurityAccountManager,

    /// <summary>
    /// MS-RPRN: Print System Remote Protocol
    /// </summary>
    PrintSpooler,

    /// <summary>
    /// MS-DFSNM: Distributed File System (DFS): Namespace Management Protocol
    /// </summary>
    NamespaceManagement,

    /// <summary>
    /// MS-FRS1: File Replication Service Protocol
    /// </summary>
    FileReplication,

    /// <summary>
    /// MS-FRS2: Distributed File System Replication Protocol
    /// </summary>
    DistributedFileReplication,

    /// <summary>
    /// MS-FSRVP: File Server Remote VSS Protocol
    /// </summary>
    VolumeShadowCopy,

    /// <summary>
    /// MS-NRPC: Netlogon Remote Protocol
    /// </summary>
    Netlogon,

    /// <summary>
    /// MS-EFSR: Encrypting File System Remote (EFSRPC) Protocol (\pipe\efsrpc)
    /// </summary>
    EncryptingFileSystem,

    /// <summary>
    /// MS-EFSR: Encrypting File System Remote (EFSRPC) Protocol (\pipe\lsarpc)
    /// </summary>
    EncryptingFileSystemLSA,

    /// <summary>
    /// 
    /// </summary>
    ServerService,

    /// <summary>
    /// 
    /// </summary>
    WorkstationService,

    /// <summary>
    /// MS-BKRP: BackupKey Remote Protocol
    /// </summary>
    BackupKey,

    /// <summary>
    /// MS-LSAD: Local Security Authority (LSA) Remote Protocol
    /// </summary>
    LocalSecurityAuthority,
}
