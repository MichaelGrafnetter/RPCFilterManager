using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Windows.Win32;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace DSInternals.Win32.RpcFilters;

using FWP_CONDITION_VALUE0 = FWP_VALUE0;

internal readonly struct FWPM_FILTER_CONDITION0
{
    /// <summary>
    /// GUID of the field to be tested.
    /// </summary>
    public readonly Guid FieldKey;

    /// <summary>
    /// Specifies the type of match to be performed.
    /// </summary>
    public readonly FWP_MATCH_TYPE MatchType;

    /// <summary>
    /// The value to match the field against.
    /// </summary>
    private readonly FWP_CONDITION_VALUE0 ConditionValue;

    /// <summary>
    /// Protocol family used by the RPC endpoint.
    /// </summary>
    public readonly RpcProtocolSequence? Protocol => this.FieldKey == PInvoke.FWPM_CONDITION_RPC_PROTOCOL ? (RpcProtocolSequence?)this.ConditionValue.UInt8Value : null;

    /// <summary>
    /// The authentication level controls how much security a client or server wants from its SSP.
    /// </summary>
    public readonly RpcAuthenticationLevel? AuthenticationLevel => this.FieldKey == PInvoke.FWPM_CONDITION_RPC_AUTH_LEVEL ? (RpcAuthenticationLevel?)this.ConditionValue.UInt8Value : null;

    /// <summary>
    /// Authentication service used for RPC connections.
    /// </summary>
    public readonly RpcAuthenticationType? AuthenticationType => this.FieldKey == PInvoke.FWPM_CONDITION_RPC_AUTH_TYPE ? (RpcAuthenticationType?)this.ConditionValue.UInt8Value : null;

    /// <summary>
    /// Remote IP address and mask.
    /// </summary>
    public readonly (IPAddress? Address, byte? Mask) RemoteAddressAndMask
    {
        get
        {
            if (this.FieldKey == PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS_V4)
            {
                long? intValue = this.ConditionValue.IntValue;
                if (intValue.HasValue)
                {
                    // Single IPv4 address.
                    var address = new IPAddress(intValue.Value);
                    return (address, FWP_V4_ADDR_AND_MASK.MaxIpv4PrefixLength);
                }
                else
                {
                    // IPv4 address and mask.
                    return this.ConditionValue.IPAddressAndMaskValue;
                }
            }
            else if (this.FieldKey == PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS_V6)
            {
                byte[]? binaryValue = this.ConditionValue.ByteArrayValue;
                if (binaryValue != null)
                {
                    // Single IPv6 address.
                    var address = new IPAddress(binaryValue);
                    return (address, FWP_V6_ADDR_AND_MASK.MaxIpv6PrefixLength);
                }
                else
                {
                    // IPv6 address and mask.
                    return this.ConditionValue.IPAddressAndMaskValue;
                }
            }
            else
            {
                // The condition does not contain a valid IP address and mask.
                return (null, null);
            }
        }
    }

    /// <summary>
    /// Local IP address and mask.
    /// </summary>
    public readonly (IPAddress? Address, byte? Mask) LocalAddressAndMask
    {
        get
        {
            if (this.FieldKey == PInvoke.FWPM_CONDITION_IP_LOCAL_ADDRESS_V4)
            {
                long? intValue = this.ConditionValue.IntValue;
                if (intValue.HasValue)
                {
                    // Single IPv4 address.
                    var address = new IPAddress(intValue.Value);
                    return (address, FWP_V4_ADDR_AND_MASK.MaxIpv4PrefixLength);
                }
                else
                {
                    // IPv4 address and mask.
                    return this.ConditionValue.IPAddressAndMaskValue;
                }
            }
            else if (this.FieldKey == PInvoke.FWPM_CONDITION_IP_LOCAL_ADDRESS_V6)
            {
                byte[]? binaryValue = this.ConditionValue.ByteArrayValue;
                if (binaryValue != null)
                {
                    // Single IPv6 address.
                    var address = new IPAddress(binaryValue);
                    return (address, FWP_V6_ADDR_AND_MASK.MaxIpv6PrefixLength);
                }
                else
                {
                    // IPv6 address and mask.
                    return this.ConditionValue.IPAddressAndMaskValue;
                }
            }
            else
            {
                // The condition does not contain a valid IP address and mask.
                return (null, null);
            }
        }
    }

    /// <summary>
    /// The local transport protocol port number.
    /// </summary>
    public readonly ushort? LocalPort => this.FieldKey == PInvoke.FWPM_CONDITION_IP_LOCAL_PORT ? this.ConditionValue.UInt16Value : null;

    /// <summary>
    /// The identification of the COM application.
    /// </summary>
    public readonly Guid? DcomAppId => this.FieldKey == PInvoke.FWPM_CONDITION_DCOM_APP_ID ? this.ConditionValue.GuidValue : null;

    /// <summary>
    /// The name of the application.
    /// </summary>
    public readonly string? ImageName => this.FieldKey == PInvoke.FWPM_CONDITION_IMAGE_NAME ? this.ConditionValue.StringValue : null;

    /// <summary>
    /// The UUID of the RPC interface.
    /// </summary>
    public readonly Guid? InterfaceUUID => this.FieldKey == PInvoke.FWPM_CONDITION_RPC_IF_UUID ? this.ConditionValue.GuidValue : null;

    /// <summary>
    /// The version of the RPC interface.
    /// </summary>
    public readonly ushort? InterfaceVersion => this.FieldKey == PInvoke.FWPM_CONDITION_RPC_IF_VERSION ? this.ConditionValue.UInt16Value : null;

    /// <summary>
    /// Reserved for internal use.
    /// </summary>
    public readonly uint? InterfaceFlag => this.FieldKey == PInvoke.FWPM_CONDITION_RPC_IF_FLAG ? this.ConditionValue.UInt32Value : null;

    /// <summary>
    /// The RPC OpNum for an RPC call made to an RPC listener.
    /// </summary>
    public readonly ushort? OperationNumber =>
            this.FieldKey == RpcFilterManager.FWPM_CONDITION_RPC_OPNUM ? this.ConditionValue.UInt16Value : null;

    /// <summary>
    /// The name of the remote named pipe.
    /// </summary>
    public readonly string? NamedPipe => this.FieldKey == PInvoke.FWPM_CONDITION_PIPE ? this.ConditionValue.StringValue : null;

    /// <summary>
    /// The identification of the remote user.
    /// </summary>
    public readonly RawSecurityDescriptor? SecurityDescriptor => this.FieldKey == PInvoke.FWPM_CONDITION_REMOTE_USER_TOKEN ? this.ConditionValue.SecurityDescriptorValue : null;

    public FWPM_FILTER_CONDITION0(RpcProtocolSequence protocol)
    {
        this.FieldKey = PInvoke.FWPM_CONDITION_RPC_PROTOCOL;
        this.MatchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL;
        this.ConditionValue = new FWP_CONDITION_VALUE0((byte)protocol);
    }

    public FWPM_FILTER_CONDITION0(RpcAuthenticationLevel authenticationLevel)
    {
        this.FieldKey = PInvoke.FWPM_CONDITION_RPC_AUTH_LEVEL;
        this.MatchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL;
        this.ConditionValue = new FWP_CONDITION_VALUE0((byte)authenticationLevel);
    }

    public FWPM_FILTER_CONDITION0(RpcAuthenticationType authenticationType)
    {
        this.FieldKey = PInvoke.FWPM_CONDITION_RPC_AUTH_TYPE;
        this.MatchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL;
        this.ConditionValue = new FWP_CONDITION_VALUE0((byte)authenticationType);
    }

    public FWPM_FILTER_CONDITION0(Guid fieldKey, ushort value)
    {
        if (fieldKey != PInvoke.FWPM_CONDITION_IP_LOCAL_PORT &&
           fieldKey != PInvoke.FWPM_CONDITION_RPC_IF_VERSION &&
           fieldKey != RpcFilterManager.FWPM_CONDITION_RPC_OPNUM)
        {
            throw new ArgumentOutOfRangeException(nameof(fieldKey), fieldKey, "The field key must be one of the predefined RPC conditions.");
        }

        this.FieldKey = fieldKey;
        this.MatchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL;
        this.ConditionValue = new FWP_CONDITION_VALUE0(value);
    }

    public FWPM_FILTER_CONDITION0(uint interfaceFlag)
    {
        this.FieldKey = PInvoke.FWPM_CONDITION_RPC_IF_FLAG;
        this.MatchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL;
        this.ConditionValue = new FWP_CONDITION_VALUE0(interfaceFlag);
    }

    private FWPM_FILTER_CONDITION0(Guid fieldKey, FWP_MATCH_TYPE matchType, FWP_CONDITION_VALUE0 conditionValue)
    {
        this.FieldKey = fieldKey;
        this.MatchType = matchType;
        this.ConditionValue = conditionValue;
    }

    public static (FWPM_FILTER_CONDITION0 condition, SafeHandle memoryHandle) Create(Guid fieldKey, Guid value)
    {
        if (fieldKey != PInvoke.FWPM_CONDITION_RPC_IF_UUID &&
            fieldKey != PInvoke.FWPM_CONDITION_DCOM_APP_ID)
        {
            throw new ArgumentOutOfRangeException(nameof(fieldKey), fieldKey, "Unexpected condition type.");
        }

        (var conditionValue, var memoryHandle) = FWP_CONDITION_VALUE0.Allocate(value);
        var condition = new FWPM_FILTER_CONDITION0(fieldKey, FWP_MATCH_TYPE.FWP_MATCH_EQUAL, conditionValue);
        return (condition, memoryHandle);
    }

    public static (FWPM_FILTER_CONDITION0 condition, SafeHandle memoryHandle) Create(Guid fieldKey, String value)
    {
        if (fieldKey != PInvoke.FWPM_CONDITION_IMAGE_NAME &&
            fieldKey != PInvoke.FWPM_CONDITION_PIPE)
        {
            throw new ArgumentOutOfRangeException(nameof(fieldKey), fieldKey, "Unexpected condition type.");
        }

        (var conditionValue, var memoryHandle) = FWP_CONDITION_VALUE0.Allocate(value);
        // TODO: String matching should be case insensitive, but FWP_MATCH_TYPE.FWP_MATCH_EQUAL_CASE_INSENSITIVE is not accepted by the system here.
        // Example: Named pipe == "\PIPE\winreg" vs. "\pipe\winreg"
        var condition = new FWPM_FILTER_CONDITION0(fieldKey, FWP_MATCH_TYPE.FWP_MATCH_EQUAL, conditionValue);
        return (condition, memoryHandle);
    }

    public static (FWPM_FILTER_CONDITION0 condition, SafeHandle memoryHandleOuter, SafeHandle memoryHandleInner) Create(RawSecurityDescriptor sd)
    {
        (var conditionValue, var memoryHandleOuter, var memoryHandleInner) = FWP_CONDITION_VALUE0.Allocate(sd);
        var condition = new FWPM_FILTER_CONDITION0(PInvoke.FWPM_CONDITION_REMOTE_USER_TOKEN, FWP_MATCH_TYPE.FWP_MATCH_EQUAL, conditionValue);
        return (condition, memoryHandleOuter, memoryHandleInner);
    }

    public static (FWPM_FILTER_CONDITION0 condition, SafeHandle? memoryHandle) Create(IPAddress address, byte? mask = null, bool isRemote = true)
    {
        // Validate the input
        if (address == null)
        {
            throw new ArgumentNullException(nameof(address));
        }

        Guid fieldKey;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            fieldKey = isRemote ? PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS_V4 : PInvoke.FWPM_CONDITION_IP_LOCAL_ADDRESS_V4;
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            fieldKey = isRemote ? PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS_V6 : PInvoke.FWPM_CONDITION_IP_LOCAL_ADDRESS_V6;
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(address), address, "The address family must be either IPv4 or IPv6.");
        }

        (FWP_CONDITION_VALUE0 conditionValue, SafeHandle? memoryHandle) = FWP_CONDITION_VALUE0.Allocate(address, mask);
        var condition = new FWPM_FILTER_CONDITION0(fieldKey, FWP_MATCH_TYPE.FWP_MATCH_EQUAL, conditionValue);
        return (condition, memoryHandle);
    }
}
