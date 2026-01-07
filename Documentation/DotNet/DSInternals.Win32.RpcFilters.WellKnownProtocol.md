# <a id="DSInternals_Win32_RpcFilters_WellKnownProtocol"></a> Enum WellKnownProtocol

Namespace: [DSInternals.Win32.RpcFilters](DSInternals.Win32.RpcFilters.md)  
Assembly: DSInternals.Win32.RpcFilters.dll  

Well-known RPC protocols.

```csharp
public enum WellKnownProtocol
```

#### Extension Methods

[WellKnownProtocolTranslator.ToInterfaceUUID\(WellKnownProtocol\)](DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator.md\#DSInternals\_Win32\_RpcFilters\_WellKnownProtocolTranslator\_ToInterfaceUUID\_DSInternals\_Win32\_RpcFilters\_WellKnownProtocol\_)

## Fields

`AddressBookReferral = 61` 

MS-OXABREF: Address Book Name Service Provider Interface (NSPI) Referral Protocol



`BackupKey = 24` 

MS-BKRP: BackupKey Remote Protocol



`CentralAccessPolicyIdentifierRetrieval = 45` 

MS-CAPR: Central Access Policy Identifier (ID) Retrieval Protocol



`ClusterConfiguration = 42` 

MC-CCFG: Server Cluster: Configuration (ClusCfg) Protocol



`ClusterManagement = 43` 

MS-CMRP: Failover Cluster: Management API (ClusAPI) Protocol



`DirectoryReplicationService = 0` 

MS-DRSR: Directory Replication Service Remote Protocol (drsuapi)



`DirectoryServicesSetup = 28` 

MS-DSSP: Directory Services Setup Remote Protocol



`DistributedFileReplication = 17` 

MS-FRS2: Distributed File System Replication Protocol



`DistributedLinkTrackingClient = 31` 

MS-DLTW: Distributed Link Tracking: Workstation Protocol



`DistributedLinkTrackingServer = 32` 

MS-DLTM: Distributed Link Tracking: Central Manager Protocol



`DnsManagement = 26` 

MS-DNSP: Domain Name Service (DNS) Server Management Protocol



`DomainRenameScript = 1` 

MS-DRSR: Directory Replication Service Remote Protocol (dsaop)



`EncryptingFileSystem = 20` 

MS-EFSR: Encrypting File System Remote (EFSRPC) Protocol (\pipe\efsrpc)



`EncryptingFileSystemLSA = 21` 

MS-EFSR: Encrypting File System Remote (EFSRPC) Protocol (\pipe\lsarpc)



`EndpointMapper = 27` 

DCERPC Endpoint Mapper



`EventLog = 6` 

MS-EVEN: EventLog Remoting Protocol



`EventLogV6 = 7` 

MS-EVEN6: EventLog Remoting Protocol Version 6.0



`FileReplicationService = 16` 

MS-FRS1: File Replication Service Protocol



`Firewall = 47` 

MS-FASP: Firewall and Advanced Security Protocol



`GroupKeyDistribution = 48` 

MS-GKDI: Group Key Distribution Protocol



`ICertAdminD = 38` 

MS-CSRA: Certificate Services Remote Administration Protocol (ICertAdminD)



`ICertAdminD2 = 39` 

MS-CSRA: Certificate Services Remote Administration Protocol (ICertAdminD2)



`ICertPassage = 35` 

MS-ICPR: ICertPassage Remote Protocol



`ICertRequestD = 36` 

MS-WCCE: Windows Client Certificate Enrollment Protocol (ICertRequestD)



`ICertRequestD2 = 37` 

MS-WCCE: Windows Client Certificate Enrollment Protocol (ICertRequestD2)



`IOCSPAdminD = 40` 

MS-OCSPA: Microsoft OCSP Administration Protocol



`ITransactionStream = 46` 

MS-COM: Component Object Model Plus (COM+) Protocol



`InitShutdown = 10` 

MS-RSP: Remote Shutdown Protocol



`LiveEventCapture = 60` 

MS-LREC: Live Remote Event Capture (LREC) Protocol



`LocalSecurityAuthority = 25` 

MS-LSAD: Local Security Authority (LSA) Remote Protocol



`MasterBrowser = 29` 

MS-BRWSA: Common Internet File System (CIFS) Browser Auxiliary Protocol



`MessageQueueManagement = 59` 

MS-MQMR: Message Queuing (MSMQ): Queue Manager Management Protocol



`MessageQueueRemoteRead = 57` 

MS-MQRR: Message Queuing (MSMQ): Queue Manager Remote Read Protocol



`MessageQueueToMessageQueue = 58` 

MS-MQQP: Message Queuing (MSMQ): Queue Manager to Queue Manager Protocol



`MimiCom = 8` 

MimiCom: Mimikatz Remote Protocol



`NameServiceProvider = 34` 

MS-NSPI: Name Service Provider Interface (NSPI) Protocol



`NamespaceManagement = 15` 

MS-DFSNM: Distributed File System (DFS): Namespace Management Protocol



`NetSchedule = 4` 

MS-TSCH: Task Scheduler Service Remoting Protocol (ATSvc)



`Netlogon = 19` 

MS-NRPC: Netlogon Remote Protocol



`OleTxTransports = 62` 

MS-CMPO: MSDTC Connection Manager: OleTx Transports Protocol



`PeerCachingAuthentication = 44` 

MS-BPAU: Background Intelligent Transfer Service (BITS) Peer-Caching: Peer Authentication Protocol



`PerformanceCounters = 56` 

MS-PCQ: Performance Counter Query Protocol



`PrintSpooler = 13` 

MS-RPRN: Print System Remote Protocol



`PrintSpoolerAsync = 14` 

MS-PAR: Print System Asynchronous Remote Protocol



`RemoteAccessManagement = 33` 

MS-RRASM: Routing and Remote Access Server (RRAS) Management Protocol



`RemoteAuthorization = 55` 

MS-RAA: Remote Authorization API Protocol



`RemoteProcedureCallLocator = 54` 

MS-RPCL: Remote Procedure Call Location Services Extensions



`RemoteRegistry = 9` 

MS-RRP: Windows Remote Registry Protocol



`SecurityAccountManager = 12` 

MS-SAMR: Security Account Manager (SAM) Remote Protocol



`ServerService = 22` 

MS-SRVSVC: Server Service Remote Protocol



`ServiceControlManager = 2` 

MS-SCMR: Service Control Manager Remote Protocol



`TaskSchedulerAgent = 3` 

MS-TSCH: Task Scheduler Service Remoting Protocol (SASec)



`TaskSchedulerService = 5` 

MS-TSCH: Task Scheduler Service Remoting Protocol (ITaskSchedulerService)



`TelnetServer = 53` 

MS-TSRAP: Telnet Server Remote Administration Protocol



`TerminalServicesGateway = 52` 

MS-TSGU: Terminal Services Gateway Server Protocol



`VolumeShadowCopy = 18` 

MS-FSRVP: File Server Remote VSS Protocol



`WebServiceControl = 49` 

MS-IISS: Internet Information Services (IIS) ServiceControl Protocol



`WebServiceInformation = 50` 

MS-IRP: Internet Information Services (IIS) Inetinfo Remote Protocol



`WindowsDeploymentServices = 41` 

MS-WDSC: Windows Deployment Services Control Protocol



`WindowsShutdown = 11` 

MS-RSP: Remote Shutdown Protocol



`WindowsTime = 30` 

MS-W32T: W32Time Remote Protocol



`Witness = 51` 

MS-SWN: Service Witness Protocol



`WorkstationService = 23` 

MS-WKSSVC: Workstation Service Remote Protocol



