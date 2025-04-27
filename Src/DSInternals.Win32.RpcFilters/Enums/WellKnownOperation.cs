namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Well-known RPC protocol operations.
/// </summary>
public enum WellKnownOperation
{
    /// <summary>
    /// The EvtRpcClearLog (MS-EVEN6) method instructs the server to clear all the events in a live channel.
    /// </summary>
    EvtRpcClearLog,

    /// <summary>
    /// The ElfrClearELFW (MS-EVEN) method instructs the server to clear an event log.
    /// </summary>
    ElfrClearELFW,

    /// <summary>
    /// The ElfrClearELFA (MS-EVEN) method instructs the server to clear an event log.
    /// </summary>
    ElfrClearELFA,

    /// <summary>
    /// The RCreateServiceW (MS-SCMR) method creates the service record in the SCM database.
    /// </summary>
    RCreateServiceW,

    /// <summary>
    /// The RCreateServiceA (MS-SCMR) method creates the service record in the SCM database.
    /// </summary>
    RCreateServiceA,

    /// <summary>
    /// The RCreateServiceWOW64A (MS-SCMR) method creates the service record for a 32-bit service on a 64-bit system.
    /// </summary>
    RCreateServiceWOW64A,

    /// <summary>
    /// The RCreateServiceWOW64W (MS-SCMR) method creates the service record for a 32-bit service on a 64-bit system.
    /// </summary>
    RCreateServiceWOW64W,

    /// <summary>
    /// The RCreateWowService (MS-SCMR) method creates a service whose binary is compiled for a specified computer architecture.
    /// </summary>
    RCreateWowService,

    /// <summary>
    /// The IDL_DRSGetNCChanges (MS-DRSR) method replicates updates from an NC replica on the server.
    /// </summary>
    IDL_DRSGetNCChanges,

    /// <summary>
    /// The IDL_DRSReplicaAdd (MS-DRSR) method adds a replication source reference for the specified NC.
    /// </summary>
    IDL_DRSReplicaAdd,

    /// <summary>
    /// The BaseRegCreateKey (MS-RRP) method creates the specified registry key.
    /// </summary>
    BaseRegCreateKey,

    /// <summary>
    /// The BaseRegSetValue (MS-RRP) method sets the data for the specified value of a registry key.
    /// </summary>
    BaseRegSetValue,

    /// <summary>
    /// The SchRpcRegisterTask (MS-TSCH) method registers a task in the Task Scheduler service.
    /// </summary>
    SchRpcRegisterTask,

    /// <summary>
    /// The NetrJobAdd (MS-TSCH) method add a single AT task to the server's task store.
    /// </summary>
    NetrJobAdd,

    /// <summary>
    /// The NetrFileEnum (MS-SRVS) method returns information about open files on a server.
    /// </summary>
    NetrFileEnum,

    /// <summary>
    /// The NetrSessionEnum (MS-SRVS) method returns information about sessions that are established on a server.
    /// </summary>
    NetrSessionEnum,

    /// <summary>
    /// The NetrShareEnum (MS-SRVS) method retrieves information about each shared resource on a server.
    /// </summary>
    NetrShareEnum,

    /// <summary>
    /// The NetrConnectionEnum (MS-SRVS) method lists the treeconnects made to a shared resource on the server.
    /// </summary>
    NetrConnectionEnum,

    /// <summary>
    /// The RpcAsyncAddPrinterDriver (MS-PAR) method installs a specified local or a remote printer driver on a specified print server.
    /// </summary>
    RpcAsyncAddPrinterDriver,

    /// <summary>
    /// The RpcAddPrinterDriverEx (MS-RPRN) method installs a printer driver on the print server.
    /// </summary>
    RpcAddPrinterDriverEx,

    /// <summary>
    /// The RpcRemoteFindFirstPrinterChangeNotification (MS-RPRN) method creates a remote change notification object that monitors changes to printer objects and sends change notifications to a print client.
    /// </summary>
    RpcRemoteFindFirstPrinterChangeNotification,

    /// <summary>
    /// The RpcRemoteFindFirstPrinterChangeNotification (MS-RPRN) method creates a remote change notification object that monitors changes to printer objects and sends change notifications to a print client.
    /// </summary>
    RpcRemoteFindFirstPrinterChangeNotificationEx,

    /// <summary>
    /// The SamrEnumerateGroupsInDomain (MS-SAMR) method enumerates all groups.
    /// </summary>
    SamrEnumerateGroupsInDomain,

    /// <summary>
    /// The SamrEnumerateUsersInDomain (MS-SAMR) method enumerates all users.
    /// </summary>
    SamrEnumerateUsersInDomain,

    /// <summary>
    /// The LsarRetrievePrivateData (MS-LSAD) method is invoked to retrieve a secret value.
    /// </summary>
    LsarRetrievePrivateData,

    /// <summary>
    /// 
    /// </summary>
    EfsRpcOpenFileRaw,

    /// <summary>
    /// 
    /// </summary>
    EfsRpcEncryptFileSrv,

    /// <summary>
    /// 
    /// </summary>
    EfsRpcDecryptFileSrv,

    /// <summary>
    /// 
    /// </summary>
    EfsRpcQueryUsersOnFile,

    /// <summary>
    /// 
    /// </summary>
    EfsRpcQueryRecoveryAgents,

    /// <summary>
    /// 
    /// </summary>
    EfsRpcRemoveUsersFromFile,

    /// <summary>
    /// 
    /// </summary>
    EfsRpcAddUsersToFile,

    /// <summary>
    /// 
    /// </summary>
    IsPathSupported,

    /// <summary>
    /// 
    /// </summary>
    IsPathShadowCopied,

    /// <summary>
    /// 
    /// </summary>
    NetrDfsAddStdRoot,

    /// <summary>
    /// 
    /// </summary>
    NetrDfsRemoveStdRoot,

    /// <summary>
    /// 
    /// </summary>
    NetrDfsAddRootTarget,

    /// <summary>
    /// 
    /// </summary>
    NetrDfsRemoveRootTarget
}
