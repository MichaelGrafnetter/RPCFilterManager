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
    ICertAdminD2,

    /// <summary>
    /// MS-OCSPA: Microsoft OCSP Administration Protocol
    /// </summary>
    IOCSPAdminD,

    /// <summary>
    /// MS-WDSC: Windows Deployment Services Control Protocol
    /// </summary>
    WindowsDeploymentServices,

    /// <summary>
    /// MC-CCFG: Server Cluster: Configuration (ClusCfg) Protocol
    /// </summary>
    ClusterConfiguration,

    /// <summary>
    /// MS-CMRP: Failover Cluster: Management API (ClusAPI) Protocol
    /// </summary>
    ClusterManagement,

    /// <summary>
    /// MS-BPAU: Background Intelligent Transfer Service (BITS) Peer-Caching: Peer Authentication Protocol
    /// </summary>
    PeerCachingAuthentication,

    /// <summary>
    /// MS-CAPR: Central Access Policy Identifier (ID) Retrieval Protocol
    /// </summary>
    CentralAccessPolicyIdentifierRetrieval,

    /// <summary>
    /// MS-COM: Component Object Model Plus (COM+) Protocol
    /// </summary>
    ITransactionStream,

    /// <summary>
    /// MS-FASP: Firewall and Advanced Security Protocol
    /// </summary>
    Firewall,

    /// <summary>
    /// MS-GKDI: Group Key Distribution Protocol
    /// </summary>
    GroupKeyDistribution,

    /// <summary>
    /// MS-IISS: Internet Information Services (IIS) ServiceControl Protocol
    /// </summary>
    WebServiceControl,

    /// <summary>
    /// MS-IRP: Internet Information Services (IIS) Inetinfo Remote Protocol
    /// </summary>
    WebServiceInformation,

    /// <summary>
    /// MS-SWN: Service Witness Protocol
    /// </summary>
    Witness,

    /// <summary>
    /// MS-TSGU: Terminal Services Gateway Server Protocol
    /// </summary>
    TerminalServicesGateway,

    /// <summary>
    /// MS-TSRAP: Telnet Server Remote Administration Protocol
    /// </summary>
    TelnetServer,

    /// <summary>
    /// MS-RPCL: Remote Procedure Call Location Services Extensions
    /// </summary>
    RemoteProcedureCallLocator,

    /// <summary>
    /// MS-RAA: Remote Authorization API Protocol
    /// </summary>
    RemoteAuthorization,

    /// <summary>
    /// MS-PCQ: Performance Counter Query Protocol
    /// </summary>
    PerformanceCounters,

    /// <summary>
    /// MS-MQRR: Message Queuing (MSMQ): Queue Manager Remote Read Protocol
    /// </summary>
    MessageQueueRemoteRead,

    /// <summary>
    /// MS-MQQP: Message Queuing (MSMQ): Queue Manager to Queue Manager Protocol
    /// </summary>
    MessageQueueToMessageQueue,

    /// <summary>
    /// MS-MQMR: Message Queuing (MSMQ): Queue Manager Management Protocol
    /// </summary>
    MessageQueueManagement,

    /// <summary>
    /// MS-LREC: Live Remote Event Capture (LREC) Protocol
    /// </summary>
    LiveEventCapture,

    /// <summary>
    /// MS-OXABREF: Address Book Name Service Provider Interface (NSPI) Referral Protocol
    /// </summary>
    AddressBookReferral,

    /// <summary>
    /// MS-CMPO: MSDTC Connection Manager: OleTx Transports Protocol
    /// </summary>
    OleTxTransports,
}
