using System.Net;
using System.Security.AccessControl;
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
        /// The UUID of the RPC interface.
        /// </summary>
        public Guid? InterfaceUUID { get; set; }

        /// <summary>
        /// Protocol family used by the RPC endpoint.
        /// </summary>
        public RpcProtocolSequence? Protocol { get; set; }

        /// <summary>
        /// The RPC OpNum for an RPC call made to an RPC listener.
        /// </summary>
        public ushort? OperationNumber { get; set; }

        /// <summary>
        /// The identification of the remote user.
        /// </summary>
        public RawSecurityDescriptor? SecurityDescriptor { get; set; }

        /// <summary>
        /// The identification of the remote user in SDDL format.
        /// </summary>
        public string? SDDL
        {
            get
            {
                return this.SecurityDescriptor?.GetSddlForm(AccessControlSections.Access);
            }
            set
            {
                this.SecurityDescriptor = new RawSecurityDescriptor(value);
            }
        }

        /// <summary>
        /// Specifies the action to be performed if all the filter conditions are true.
        /// </summary>
        public RpcFilterAction Action { get; set; }

        /// <summary>
        /// Indicates whether incoming RPC calls are audited as part of C2 and common criteria compliance.
        /// </summary>
        public bool Audit { get; set; }

        /// <summary>
        /// Indicates whether the filter is persistent, that is, it survives across BFE stop/start.
        /// </summary>
        public bool IsPersistent { get; set; }

        /// <summary>
        /// Indicates whether the filter is enforced at boot-time, even before BFE starts.
        /// </summary>
        public bool IsBootTimeEnforced { get; set; }

        /// <summary>
        /// Optional identifier of the policy provider that manages this filter.
        /// </summary>
        public Guid? ProviderKey { get; set; }

        /// <summary>
        /// The weight indicates the priority of the filter, where higher-numbered weights have higher priorities.
        /// </summary>
        public ulong? Weight { get; set; }

        /// <summary>
        /// Contains the weight assigned to the filter.
        /// </summary>
        public ulong? EffectiveWeight { get; internal set; }

        /// <summary>
        /// The authentication level controls how much security a client or server wants from its SSP.
        /// </summary>
        public RpcAuthenticationLevel? AuthenticationLevel { get; set; }

        /// <summary>
        /// Authentication service used for RPC connections.
        /// </summary>
        public RpcAuthenticationType? AuthenticationType { get; set; }

        /// <summary>
        /// The name of the remote named pipe.
        /// </summary>
        public string? NamedPipe { get; set; }

        /// <summary>
        /// The remote IP address. 
        /// </summary>
        public IPAddress? RemoteAddress { get; set; }

        /// <summary>
        /// The local IP address. 
        /// </summary>
        public IPAddress? LocalAddress { get; set; }

        /// <summary>
        /// The local transport protocol port number.
        /// </summary>
        public ushort? LocalPort { get; set; }

        /// <summary>
        /// The version of the RPC interface.
        /// </summary>
        public ushort? InterfaceVersion { get; set; }

        /// <summary>
        /// Reserved for internal use.
        /// </summary>
        public uint? InterfaceFlag { get; set; }

        /// <summary>
        /// The name of the application.
        /// </summary>
        public string? ImageName { get; set; }

        /// <summary>
        /// The identification of the COM application.
        /// </summary>
        public Guid? DcomAppId { get; set; }

        public RpcFilter()
        {
            this.FilterKey = Guid.NewGuid();
            this.Name = DefaultName;
            this.Description = DefaultDescription;
        }

        internal static RpcFilter Create(FWPM_FILTER0 nativeFilter)
        {
            // Process basic properties
            var filter = new RpcFilter()
            {
                FilterKey = nativeFilter.FilterKey,
                FilterId = nativeFilter.FilterId,
                Name = nativeFilter.DisplayData.Name ?? DefaultName,
                Description = nativeFilter.DisplayData.Description,
                IsPersistent = nativeFilter.Flags.HasFlag(FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_PERSISTENT),
                IsBootTimeEnforced = nativeFilter.Flags.HasFlag(FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_BOOTTIME),
                Audit = nativeFilter.SubLayerKey == PInvoke.FWPM_SUBLAYER_RPC_AUDIT,
                ProviderKey = nativeFilter.ProviderKey,
                Weight = nativeFilter.Weight.UInt64Value,
                Action = (RpcFilterAction)nativeFilter.Action.Type,
                EffectiveWeight = nativeFilter.EffectiveWeight.UInt64Value,
            };

            // Deflate filter conditions
            // Note: Drops info about the operators in the process, but EQUALS is used in most cases.
            foreach (var condition in nativeFilter.FilterCondition)
            {
                if (condition.FieldKey == PInvoke.FWPM_CONDITION_RPC_PROTOCOL) {
                    filter.Protocol = condition.Protocol;
                }
                else if (condition.FieldKey == PInvoke.FWPM_CONDITION_PIPE)
                {
                    filter.NamedPipe = condition.NamedPipe;
                }
                else if (condition.FieldKey == PInvoke.FWPM_CONDITION_RPC_IF_UUID)
                {
                    filter.InterfaceUUID = condition.InterfaceUUID;
                }
                else if (condition.FieldKey == PInvoke.FWPM_CONDITION_RPC_IF_VERSION)
                {
                    filter.InterfaceVersion = condition.InterfaceVersion;
                }
                else if (condition.FieldKey == PInvoke.FWPM_CONDITION_RPC_IF_FLAG)
                {
                    filter.InterfaceFlag = condition.InterfaceFlag;
                }
                else if (condition.FieldKey == Guid.Parse("d58efb76-aab7-4148-a87e-9581134129b9"))
                {
                    // TODO: Use the FWPM_CONDITION_RPC_OPNUM constant once it gets into the API.
                    filter.OperationNumber = condition.OperationNumber;
                }
                else if (condition.FieldKey == PInvoke.FWPM_CONDITION_RPC_AUTH_LEVEL) {
                    filter.AuthenticationLevel = condition.AuthenticationLevel;
                }
                else if (condition.FieldKey == PInvoke.FWPM_CONDITION_RPC_AUTH_TYPE) {
                    filter.AuthenticationType = condition.AuthenticationType;
                }
                else if (condition.FieldKey == PInvoke.FWPM_CONDITION_REMOTE_USER_TOKEN)
                {
                    filter.SecurityDescriptor = condition.SecurityDescriptor;
                }
                else if (condition.FieldKey == PInvoke.FWPM_CONDITION_RPC_SERVER_PORT)
                {
                    filter.LocalPort = condition.LocalPort;
                }
                else if (condition.FieldKey == PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS_V4 || condition.FieldKey == PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS_V6)
                {
                    filter.RemoteAddress = condition.RemoteAddress;
                }
                else if (condition.FieldKey == PInvoke.FWPM_CONDITION_IP_LOCAL_ADDRESS_V4 || condition.FieldKey == PInvoke.FWPM_CONDITION_IP_LOCAL_ADDRESS_V6)
                {
                    filter.LocalAddress = condition.LocalAddress;
                }
                else if (condition.FieldKey == PInvoke.FWPM_CONDITION_DCOM_APP_ID)
                {
                    filter.DcomAppId = condition.DcomAppId;
                }
                else if (condition.FieldKey == PInvoke.FWPM_CONDITION_IMAGE_NAME)
                {
                    filter.ImageName = condition.ImageName;
                }
            }

            return filter;
        }
    }
}
