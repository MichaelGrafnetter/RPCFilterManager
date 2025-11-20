namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Audit options for RPC filters.
/// </summary>
[Flags]
public enum RpcFilterAuditOptions : ulong
{
    /// <summary>
    /// Auditing is disabled for this filter.
    /// </summary>
    Disabled = 0,

    /// <summary>
    /// Auditing is enabled for this filter.
    /// </summary>
    Enabled = RpcFilterManager.FWPM_CONTEXT_RPC_AUDIT_ENABLED,

    /// <summary>
    /// Parameter buffer auditing is enabled for this filter.
    /// </summary>
    /// <remarks>
    /// This flag can only be set if auditing is also enabled.
    /// </remarks>
    Parameters = RpcFilterManager.FWPM_CONTEXT_RPC_AUDIT_BUFFER_ENABLED,

    /// <summary>
    /// Auditing with parameters is enabled for this filter.
    /// </summary>
    EnabledWithParams = Enabled | Parameters
}
