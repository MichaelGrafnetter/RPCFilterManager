using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Match types (operators) for numeric values.
/// </summary>
public enum NumericMatchType
{
    /// <summary>
    /// The values are equal.
    /// </summary>
    Equals = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,

    /// <summary>
    /// The value is less than the specified value.
    /// </summary>
    LessThan = FWP_MATCH_TYPE.FWP_MATCH_LESS,

    /// <summary>
    /// The value is less than or equal to the specified value.
    /// </summary>
    LessOrEquals = FWP_MATCH_TYPE.FWP_MATCH_LESS_OR_EQUAL,

    /// <summary>
    /// The value is greater than the specified value.
    /// </summary>
    GreaterThan = FWP_MATCH_TYPE.FWP_MATCH_GREATER,

    /// <summary>
    /// The value is greater than or equal to the specified value.
    /// </summary>
    GreaterOrEquals = FWP_MATCH_TYPE.FWP_MATCH_GREATER_OR_EQUAL,
}
