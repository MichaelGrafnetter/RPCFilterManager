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

    IDL_DRSAddEntry,

    IDL_DRSReplicaAdd,

    BaseRegCreateKey,

    BaseRegSetValue,

    SchRpcRegisterTask,

    NetrJobAdd,

    NetrFileEnum,

    NetrSessionEnum,

    NetrShareEnum,

    NetrConnectionEnum,

    RpcAsyncAddPrinterDriver,

    RpcAddPrinterDriverEx,

    RpcRemoteFindFirstPrinterChangeNotification,

    RpcRemoteFindFirstPrinterChangeNotificationEx,

    SamrEnumerateGroupsInDomain,

    SamrEnumerateUsersInDomain,

    LsarRetrievePrivateData,

    EfsRpcOpenFileRaw,

    EfsRpcEncryptFileSrv,

    EfsRpcDecryptFileSrv,

    EfsRpcQueryUsersOnFile,

    EfsRpcQueryRecoveryAgents,

    EfsRpcRemoveUsersFromFile,

    EfsRpcAddUsersToFile,

    IsPathSupported,

    IsPathShadowCopied,

    NetrDfsAddStdRoot,

    NetrDfsRemoveStdRoot
}
