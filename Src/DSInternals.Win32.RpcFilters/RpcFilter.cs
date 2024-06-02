using System.Net;
using System.Security.Principal;
using Windows.Win32;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace DSInternals.Win32.RpcFilters
{
    /// <summary>
    /// Stores the state associated with a RPC filter.
    /// </summary>
    public class RpcFilter
    {
        private const string DefaultName = "RPCFilter";
        private const string DefaultDescription = "RPC Filter";

        /// <summary>
        /// Unique identifier of the filter.
        /// </summary>
        public Guid FilterKey;

        /// <summary>
        /// Locally unique identifier of the filter.
        /// </summary>
        public ulong? FilterId { get; internal set; }

        /// <summary>
        /// Human-readable RPC filter name.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Optional filter description.
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// Indicates whether the filter is persistent, that is, it survives across BFE stop/start.
        /// </summary>
        public bool IsPersistent { get; set; }

        /// <summary>
        /// Indicates whether the filter is enforced at boot-time, even before BFE starts.
        /// </summary>
        public bool IsBootTimeEnforced { get; set; }

        /// <summary>
        /// Indicates whether incoming RPC calls are audited as part of C2 and common criteria compliance.
        /// </summary>
        public bool Audit { get; set; }

        /// <summary>
        /// Optional identifier of the policy provider that manages this filter.
        /// </summary>
        public Guid? ProviderKey { get; set; }

        /// <summary>
        /// The weight indicates the priority of the filter, where higher-numbered weights have higher priorities.
        /// </summary>
        public ulong? Weight { get; set; }

        /// <summary>
        /// Specifies the action to be performed if all the filter conditions are true.
        /// </summary>
        public RpcFilterAction Action { get; set; }

        /// <summary>
        /// Contains the weight assigned to the filter.
        /// </summary>
        public ulong EffectiveWeight { get; internal set; }

        public int? Protocol { get; set; }

        public int? AuthenticationLevel { get; set; }

        public int? AuthenticationType { get; set; }

        public string? NamedPipe { get; set; }

        public IPAddress? RemoteAddress { get; set; }

        public int? OperationNumber { get; set; }

        public Guid? InterfaceUUID { get; set; }

        public SecurityIdentifier Principal { get; set; }

        public RpcFilter()
        {
            this.FilterKey = Guid.NewGuid();
            this.Name = DefaultName;
            this.Description = DefaultDescription;
        }

        internal static RpcFilter Create(FWPM_FILTER0 nativeFilter)
        {
            return new RpcFilter()
            {
                FilterKey = nativeFilter.FilterKey,
                FilterId = nativeFilter.FilterId,
                Name = nativeFilter.DisplayData.Name ?? DefaultName,
                Description = nativeFilter.DisplayData.Description,
                IsPersistent = nativeFilter.Flags.HasFlag(FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_PERSISTENT),
                IsBootTimeEnforced = nativeFilter.Flags.HasFlag(FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_BOOTTIME),
                Audit = nativeFilter.SubLayerKey == PInvoke.FWPM_SUBLAYER_RPC_AUDIT,
                ProviderKey = nativeFilter.ProviderKey,
                Weight = nativeFilter.Weight.ToUInt64(),
                Action = (RpcFilterAction)nativeFilter.Action.Type,
                EffectiveWeight = nativeFilter.EffectiveWeight.ToUInt64().Value,
            };
        }
    }
}
