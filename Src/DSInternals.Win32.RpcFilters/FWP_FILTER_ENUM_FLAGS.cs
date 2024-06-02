using Windows.Win32;

namespace DSInternals.Win32.RpcFilters
{
    /// <summary>
    /// Filter enumeration flags.
    /// </summary>
    [Flags]
    internal enum FWP_FILTER_ENUM_FLAGS : uint
    {
        /// <summary>
        /// Only return the terminating filter with the highest weight. 
        /// </summary>
        FWP_FILTER_ENUM_FLAG_BEST_TERMINATING_MATCH = PInvoke.FWP_FILTER_ENUM_FLAG_BEST_TERMINATING_MATCH,

        /// <summary>
        /// Return all matching filters sorted by weight (highest to lowest). 
        /// </summary>
        FWP_FILTER_ENUM_FLAG_SORTED = PInvoke.FWP_FILTER_ENUM_FLAG_SORTED,

        /// <summary>
        /// Return only boot-time filters.
        /// </summary>
        FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY = PInvoke.FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY,

        /// <summary>
        /// Include boot-time filters.
        /// </summary>
        FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME = PInvoke.FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME,

        /// <summary>
        /// Include disabled filters.
        /// </summary>
        FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED = PInvoke.FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,

        /// <summary>
        /// Return the highest-priority filter.
        /// </summary>
        FWP_FILTER_ENUM_VALID_FLAGS = FWP_FILTER_ENUM_FLAG_BEST_TERMINATING_MATCH | FWP_FILTER_ENUM_FLAG_SORTED
    }
}
