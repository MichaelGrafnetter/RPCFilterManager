using System.Runtime.InteropServices;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace DSInternals.Win32.RpcFilters
{
    /// <summary>
    /// Specifies the action taken if all the filter conditions are true.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_ACTION0
    {
        /// <summary>
        /// Action to be performed.
        /// </summary>
        public FWP_ACTION_TYPE Type;

        public FWPM_ACTION0_UNION Reference;

        [StructLayout(LayoutKind.Explicit)]
        public struct FWPM_ACTION0_UNION
        {
            /// <summary>
            /// An arbitrary GUID chosen by the policy provider.
            /// </summary>
            [FieldOffset(0)]
            public Guid FilterType;

            /// <summary>
            /// The GUID for a valid callout in the layer.
            /// </summary>
            [FieldOffset(0)]
            public Guid CalloutKey;
        }

        public FWPM_ACTION0(bool permit)
        {
            this.Type = permit ? FWP_ACTION_TYPE.FWP_ACTION_PERMIT : FWP_ACTION_TYPE.FWP_ACTION_BLOCK;
        }

        public FWPM_ACTION0(RpcFilterAction action)
        {
            this.Type = (FWP_ACTION_TYPE)action;
        }
    }
}
