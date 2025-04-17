using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// RPC filter action type.
/// </summary>
public enum RpcFilterAction : uint
{
    /// <summary>
    /// Permit the traffic.
    /// </summary>
    Permit = FWP_ACTION_TYPE.FWP_ACTION_PERMIT,

    /// <summary>
    /// Block the traffic.
    /// </summary>
    Block = FWP_ACTION_TYPE.FWP_ACTION_BLOCK,

    /// <summary>
    /// Invoke a callout that always returns block or permit.
    /// </summary>
    CalloutTerminating = FWP_ACTION_TYPE.FWP_ACTION_CALLOUT_TERMINATING,

    /// <summary>
    /// Invoke a callout that never returns block or permit.
    /// </summary>
    CalloutInspection = FWP_ACTION_TYPE.FWP_ACTION_CALLOUT_INSPECTION,

    /// <summary>
    /// Invoke a callout that may return block or permit.
    /// </summary>
    CalloutUnknown = FWP_ACTION_TYPE.FWP_ACTION_CALLOUT_UNKNOWN
}
