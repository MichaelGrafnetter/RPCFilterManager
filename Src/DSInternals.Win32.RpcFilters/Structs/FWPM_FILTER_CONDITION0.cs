using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Net.Sockets;
using Windows.Win32;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace DSInternals.Win32.RpcFilters
{
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
        /// The remote IP address. 
        /// </summary>
        public readonly IPAddress? RemoteAddress
        {
            get
            {
                if (this.FieldKey == PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS_V4)
                {
                    if ( this.ConditionValue.Type == FWP_DATA_TYPE.FWP_UINT32)
                    {
#pragma warning disable CS8629 // Nullable value type may be null.
                        return new IPAddress(this.ConditionValue.IntValue.Value);
#pragma warning restore CS8629 // Nullable value type may be null.
                    }
                    else if(this.ConditionValue.Type == FWP_DATA_TYPE.FWP_V4_ADDR_MASK)
                    {
                        // TODO: Parse the mask (ranges do not work yet in Windows)
                        return null;
                    }
                }
                else if (this.FieldKey == PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS_V6)
                {
                    if (this.ConditionValue.Type == FWP_DATA_TYPE.FWP_BYTE_ARRAY16_TYPE)
                    {
                        return new IPAddress(this.ConditionValue.ByteArrayValue);
                    }
                    else if (this.ConditionValue.Type == FWP_DATA_TYPE.FWP_V6_ADDR_MASK)
                    {
                        // TODO: Parse the IPv6 address mask (ranges do not work yet in Windows)
                        return null;
                    }
                }
            
                // The condition does not contain a valid IP address.
                return null;
            }
        }

        /// <summary>
        /// The local IP address. 
        /// </summary>
        public readonly IPAddress? LocalAddress
        {
            get
            {
                if (this.FieldKey == PInvoke.FWPM_CONDITION_IP_LOCAL_ADDRESS_V4)
                {
                    if (this.ConditionValue.Type == FWP_DATA_TYPE.FWP_UINT32)
                    {
#pragma warning disable CS8629 // Nullable value type may be null.
                        return new IPAddress(this.ConditionValue.IntValue.Value);
#pragma warning restore CS8629 // Nullable value type may be null.
                    }
                    else if (this.ConditionValue.Type == FWP_DATA_TYPE.FWP_V4_ADDR_MASK)
                    {
                        // TODO: Parse the mask (ranges do not work yet in Windows)
                        return null;
                    }
                }
                else if (this.FieldKey == PInvoke.FWPM_CONDITION_IP_LOCAL_ADDRESS_V6)
                {
                    if (this.ConditionValue.Type == FWP_DATA_TYPE.FWP_BYTE_ARRAY16_TYPE)
                    {
                        return new IPAddress(this.ConditionValue.ByteArrayValue);
                    }
                    else if (this.ConditionValue.Type == FWP_DATA_TYPE.FWP_V6_ADDR_MASK)
                    {
                        // TODO: Parse the IPv6 address mask (ranges do not work yet in Windows)
                        return null;
                    }
                }

                // The condition does not contain a valid IP address.
                return null;
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
            var condition = new FWPM_FILTER_CONDITION0(fieldKey, FWP_MATCH_TYPE.FWP_MATCH_EQUAL, conditionValue);
            return (condition, memoryHandle);
        }

        public static (FWPM_FILTER_CONDITION0 condition, SafeHandle memoryHandle) Create(RawSecurityDescriptor sd)
        {
            (var conditionValue, var memoryHandle) = FWP_CONDITION_VALUE0.Allocate(sd);
            var condition = new FWPM_FILTER_CONDITION0(PInvoke.FWPM_CONDITION_REMOTE_USER_TOKEN, FWP_MATCH_TYPE.FWP_MATCH_EQUAL, conditionValue);
            return (condition, memoryHandle);
        }

        public static (FWPM_FILTER_CONDITION0 condition, SafeHandle? memoryHandle) Create(IPAddress address, bool isRemote = true)
        {
            // Validate the input
            if(address == null) throw new ArgumentNullException(nameof(address));

            if(address.AddressFamily == AddressFamily.InterNetwork)
            {
                Guid fieldKey = isRemote ? PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS_V4 : PInvoke.FWPM_CONDITION_IP_LOCAL_ADDRESS_V4;
                byte[] binaryAddress = address.GetAddressBytes();
                uint byteAddress = BitConverter.ToUInt32(binaryAddress, 0);
                var conditionValue = new FWP_CONDITION_VALUE0(byteAddress);
                var condition = new FWPM_FILTER_CONDITION0(fieldKey, FWP_MATCH_TYPE.FWP_MATCH_EQUAL, conditionValue);
                return (condition, null);
            }
            else if(address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                Guid fieldKey = isRemote ? PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS_V6 : PInvoke.FWPM_CONDITION_IP_LOCAL_ADDRESS_V6;
                byte[] binaryAddress = address.GetAddressBytes();
                (var conditionValue, var memoryHandle) = FWP_CONDITION_VALUE0.Allocate(binaryAddress);
                var condition = new FWPM_FILTER_CONDITION0(fieldKey, FWP_MATCH_TYPE.FWP_MATCH_EQUAL, conditionValue);
                return (condition, memoryHandle);
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(address), address, "The address family must be either IPv4 or IPv6.");
            }
        }
    }
}
