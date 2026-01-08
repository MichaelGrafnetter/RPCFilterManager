using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Stores the state associated with a RPC filter.
/// </summary>
public sealed class RpcFilter
{
    /// <summary>
    /// Default name of a newly created filter.
    /// </summary>
    public const string DefaultName = "RPCFilter";

    /// <summary>
    /// Default description of a newly created filter.
    /// </summary>
    public const string DefaultDescription = "RPC Filter";

    /// <summary>
    /// Unique identifier of the filter.
    /// </summary>
    public Guid FilterKey { get; set; }

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
    /// The name of the RPC interface.
    /// </summary>
    public string? InterfaceName => this.InterfaceUUID.ToProtocolName(false);

    /// <summary>
    /// Protocol family used by the RPC endpoint.
    /// </summary>
    public RpcProtocolSequence? Transport { get; set; }

    /// <summary>
    /// The RPC OpNum for an RPC call made to an RPC listener.
    /// </summary>
    public ushort? OperationNumber { get; set; }

    /// <summary>
    /// The name of the RPC operation.
    /// </summary>
    public string? OperationName => WellKnownProtocolTranslator.ToOperationName(this.InterfaceUUID, this.OperationNumber, false);

    /// <summary>
    /// The identification of the remote user.
    /// </summary>
    public RawSecurityDescriptor? SecurityDescriptor { get; set; }

    /// <summary>
    /// Indicates whether the security descriptor should be negated.
    /// </summary>
    public bool SecurityDescriptorNegativeMatch { get; set; }

    /// <summary>
    /// The security descriptor operator as a string.
    /// </summary>
    /// <remarks>This read-only property is for display purposes only.</remarks>
    public string SecurityDescriptorOperator => this.SecurityDescriptorNegativeMatch ? "<>" : "=";

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
            this.SecurityDescriptor = string.IsNullOrEmpty(value) ? null : new RawSecurityDescriptor(value);
        }
    }

    /// <summary>
    /// Specifies the action to be performed if all the filter conditions are true.
    /// </summary>
    public RpcFilterAction Action { get; set; }

    /// <summary>
    /// Indicates whether incoming RPC calls and their parameters are audited as part of C2 and common criteria compliance.
    /// </summary>
    public RpcFilterAuditOptions Audit { get; set; }

    /// <summary>
    /// Indicates whether the filter is persistent, that is, it survives across BFE stop/start.
    /// </summary>
    public bool IsPersistent { get; set; }

    /// <summary>
    /// Indicates whether the filter is enforced at boot-time, even before BFE starts.
    /// </summary>
    public bool IsBootTimeEnforced { get; set; }

    /// <summary>
    /// Indicates whether the filter is disabled.
    /// </summary>
    /// <remarks>
    /// A provider's filters are disabled when the BFE starts if the provider has no associated Windows service name, or if the associated service is not set to auto-start.
    /// This flag cannot be set when adding new filters. It can only be returned by BFE when getting or enumerating filters.
    /// </remarks>
    public bool IsDisabled { get; internal set; }

    /// <summary>
    /// Optional identifier of the policy provider that manages this filter.
    /// </summary>
    public Guid? ProviderKey { get; internal set; }

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
    /// The match type (operator) for the authentication level.
    /// </summary>
    public NumericMatchType AuthenticationLevelMatchType { get; set; } = NumericMatchType.Equals;

    /// <summary>
    /// The authentication level operator as a string.
    /// </summary>
    /// <remarks>This read-only property is for display purposes only.</remarks>
    public string AuthenticationLevelOperator => this.AuthenticationLevelMatchType switch
    {
        NumericMatchType.Equals => "=",
        NumericMatchType.LessThan => "<",
        NumericMatchType.LessOrEquals => "<=",
        NumericMatchType.GreaterThan => ">",
        NumericMatchType.GreaterOrEquals => ">=",
        _ => "?" // Undefined operator
    };

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
    /// The remote IP address mask.
    /// </summary>
    public byte? RemoteAddressMask { get; set; }

    /// <summary>
    /// The local IP address.
    /// </summary>
    public IPAddress? LocalAddress { get; set; }

    /// <summary>
    /// The local IP address mask.
    /// </summary>
    public byte? LocalAddressMask { get; set; }

#if NET8_0_OR_GREATER
    // The IPNetwork class is only available in .NET 8.0 and later.

    /// <summary>
    /// The remote IP address and mask.
    /// </summary>
    public IPNetwork? RemoteNetwork
    {
        get
        {
            if(this.RemoteAddress == null)
            {
                return null;
            }

            int prefixLength = this.RemoteAddressMask ?? this.RemoteAddress.AddressFamily switch
            {
                AddressFamily.InterNetwork => FWP_V4_ADDR_AND_MASK.MaxIpv4PrefixLength,
                AddressFamily.InterNetworkV6 => FWP_V6_ADDR_AND_MASK.MaxIpv6PrefixLength,
                _ => 0
            };

            return new IPNetwork(this.RemoteAddress, prefixLength);
        }
        set
        {
            if (value.HasValue)
            {
                this.RemoteAddress = value.Value.BaseAddress;
                this.RemoteAddressMask = (byte) value.Value.PrefixLength;
            }
            else
            {
                this.RemoteAddress = null;
                this.RemoteAddressMask = null;
            }
        }
    }

    /// <summary>
    /// The local IP address and mask.
    /// </summary>
    public IPNetwork? LocalNetwork
    {
        get
        {
            if (this.LocalAddress == null)
            {
                return null;
            }

            int prefixLength = this.LocalAddressMask ?? this.LocalAddress.AddressFamily switch
            {
                AddressFamily.InterNetwork => FWP_V4_ADDR_AND_MASK.MaxIpv4PrefixLength,
                AddressFamily.InterNetworkV6 => FWP_V6_ADDR_AND_MASK.MaxIpv6PrefixLength,
                _ => 0
            };

            return new IPNetwork(this.LocalAddress, prefixLength);
        }
        set
        {
            if (value.HasValue)
            {
                this.LocalAddress = value.Value.BaseAddress;
                this.LocalAddressMask = (byte)value.Value.PrefixLength;
            }
            else
            {
                this.LocalAddress = null;
                this.LocalAddressMask = null;
            }
        }
    }
#else
    /// <summary>
    /// The remote IP address and mask.
    /// </summary>
    public string? RemoteNetwork
    {
        get
        {
            if (this.RemoteAddress == null)
            {
                return null;
            }

            byte prefixLength = this.RemoteAddressMask ?? this.RemoteAddress.AddressFamily switch
            {
                AddressFamily.InterNetwork => FWP_V4_ADDR_AND_MASK.MaxIpv4PrefixLength,
                AddressFamily.InterNetworkV6 => FWP_V6_ADDR_AND_MASK.MaxIpv6PrefixLength,
                _ => 0
            };

            return $"{this.RemoteAddress}/{prefixLength}";
        }
    }

    /// <summary>
    /// The local IP address and mask.
    /// </summary>
    public string? LocalNetwork
    {
        get
        {
            if (this.LocalAddress == null)
            {
                return null;
            }

            int prefixLength = this.LocalAddressMask ?? this.LocalAddress.AddressFamily switch
            {
                AddressFamily.InterNetwork => FWP_V4_ADDR_AND_MASK.MaxIpv4PrefixLength,
                AddressFamily.InterNetworkV6 => FWP_V6_ADDR_AND_MASK.MaxIpv6PrefixLength,
                _ => 0
            };

            return $"{this.LocalAddress}/{prefixLength}";
        }
    }
#endif

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

    /// <summary>
    /// Constructs a new instance of the <see cref="RpcFilter"/> class with default values.
    /// </summary>
    public RpcFilter()
    {
        this.FilterKey = Guid.NewGuid();
        this.Name = DefaultName;
        this.Description = DefaultDescription;
    }
}
