using System.Runtime.InteropServices;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;


namespace DSInternals.Win32.RpcFilters
{
    /// <summary>
    /// Stores the state associated with a filter.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 0)]
    internal struct FWPM_FILTER0
    {
        /// <summary>
        /// Uniquely identifies the filter.
        /// </summary>
        public Guid FilterKey;

        /// <summary>
        /// Human-readable annotations associated with the filter.
        /// </summary>
        public FWPM_DISPLAY_DATA0 DisplayData;
        
        /// <summary>
        /// Filter flags.
        /// </summary>
        public FWPM_FILTER_FLAGS Flags;

        private IntPtr providerKey;

        /// <summary>
        /// Optional GUID of the policy provider that manages this filter.
        /// </summary>
        public Guid? ProviderKey
        {
            get
            {
                return this.providerKey != IntPtr.Zero ? Marshal.PtrToStructure<Guid>(this.providerKey) : null;
            }
        }

        /// <summary>
        /// Optional provider-specific data used by providers to store additional context information with the object.
        /// </summary>
        [MarshalAs(UnmanagedType.Struct)]
        public FWP_BYTE_BLOB ProviderData;

        /// <summary>
        /// GUID of the layer where the filter resides.
        /// </summary>
        public Guid LayerKey;

        /// <summary>
        /// GUID of the sub-layer where the filter resides.
        /// </summary>
        public Guid SubLayerKey;

        /// <summary>
        /// The weight indicates the priority of the filter, where higher-numbered weights have higher priorities.
        /// </summary>
        public FWP_VALUE0 Weight;

        /// <summary>
        /// Number of filter conditions.
        /// </summary>
        public int NumFilterConditions;

        /// <summary>
        /// Array of all the filtering conditions.
        /// </summary>
        public IntPtr FilterCondition;
        
        /// <summary>
        /// Specifies the action to be performed if all the filter conditions are true.
        /// </summary>
        public FWPM_ACTION0 Action;
        
        /// <summary>
        /// Filter context.
        /// </summary>
        public FWPM_FILTER0_UNION Context;

        [StructLayout(LayoutKind.Explicit)]
        public struct FWPM_FILTER0_UNION
        {
            /// <summary>
            /// Available when the filter does not have provider context information.
            /// </summary>
            [FieldOffset(0)]
            public ulong rawContext;

            /// <summary>
            /// Available when the filter has provider context information.
            /// </summary>
            [FieldOffset(0)]
            public Guid providerContextKey;
        }

        /// <summary>
        /// Reserved for system use.
        /// </summary>
        public IntPtr Reserved;

        /// <summary>
        /// LUID identifying the filter.
        /// </summary>
        public ulong FilterId;

        /// <summary>
        /// Contains the weight assigned to the filter.
        /// </summary>
        public FWP_VALUE0 EffectiveWeight;
    }
}
