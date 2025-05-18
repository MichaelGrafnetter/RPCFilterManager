namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Well-known RPC protocols.
/// </summary>
public enum WellKnownProtocol
{
    /// <summary>
    /// MS-DRSR: Directory Replication Service Remote Protocol (drsuapi)
    /// </summary>
    DirectoryReplicationService,

    /// <summary>
    /// MS-DRSR: Directory Replication Service Remote Protocol (dsaop)
    /// </summary>
    DomainRenameScript,

    /// <summary>
    /// MS-SCMR: Service Control Manager Remote Protocol
    /// </summary>
    ServiceControlManager,

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
    RemoteRegistry,

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
    /// MS-PAR: Print System Asynchronous Remote Protocol
    /// </summary>
    PrintSpoolerAsync,

    /// <summary>
    /// MS-DFSNM: Distributed File System (DFS): Namespace Management Protocol
    /// </summary>
    NamespaceManagement,

    /// <summary>
    /// MS-FRS1: File Replication Service Protocol
    /// </summary>
    FileReplicationService,

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
    /// MS-SRVSVC: Server Service Remote Protocol
    /// </summary>
    ServerService,

    /// <summary>
    /// MS-WKSSVC: Workstation Service Remote Protocol
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

    /// <summary>
    /// MS-DNSP: Domain Name Service (DNS) Server Management Protocol
    /// </summary>
    DnsManagement,

    /// <summary>
    /// DCERPC Endpoint Mapper
    /// </summary>
    EndpointMapper,

    /// <summary>
    /// MS-DSSP: Directory Services Setup Remote Protocol
    /// </summary>
    DirectoryServicesSetup,

    /// <summary>
    /// MS-BRWSA: Common Internet File System (CIFS) Browser Auxiliary Protocol
    /// </summary>
    MasterBrowser,

    /// <summary>
    /// MS-W32T: W32Time Remote Protocol
    /// </summary>
    WindowsTime,

    /// <summary>
    /// MS-DLTW: Distributed Link Tracking: Workstation Protocol
    /// </summary>
    DistributedLinkTrackingClient,

    /// <summary>
    /// MS-DLTM: Distributed Link Tracking: Central Manager Protocol
    /// </summary>
    DistributedLinkTrackingServer,

    /// <summary>
    /// MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol
    /// </summary>
    RemoteAccessManagement,

    /// <summary>
    /// MS-NSPI: Name Service Provider Interface (NSPI) Protocol
    /// </summary>
    NameServiceProvider,

    /// <summary>
    /// MS-ICPR: ICertPassage Remote Protocol
    /// </summary>
    ICertPassage,

    /// <summary>
    /// MS-WCCE: Windows Client Certificate Enrollment Protocol (ICertRequestD)
    /// </summary>
    ICertRequestD,

    /// <summary>
    /// MS-WCCE: Windows Client Certificate Enrollment Protocol (ICertRequestD2)
    /// </summary>
    ICertRequestD2,

    /// <summary>
    /// MS-CSRA: Certificate Services Remote Administration Protocol (ICertAdminD)
    /// </summary>
    ICertAdminD,

    /// <summary>
    /// MS-CSRA: Certificate Services Remote Administration Protocol (ICertAdminD2)
    /// </summary>
    ICertAdminD2
}
