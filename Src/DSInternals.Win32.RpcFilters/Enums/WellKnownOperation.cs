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
    /// The IDL_DRSGetNCChanges (MS-DRSR) method replicates updates from an NC replica on the server.
    /// </summary>
    IDL_DRSGetNCChanges,

    // TODO: Add support for more operations
}
