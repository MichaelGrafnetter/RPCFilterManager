using System.Net;
using System.Security.Principal;
using Windows.Win32;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace DSInternals.Win32.RpcFilters
{
    using FWP_CONDITION_VALUE0 = FWP_VALUE0;

    internal struct FWPM_FILTER_CONDITION0
    {
        /// <summary>
        /// GUID of the field to be tested.
        /// </summary>
        public Guid FieldKey;

        /// <summary>
        /// Specifies the type of match to be performed.
        /// </summary>
        public FWP_MATCH_TYPE MatchType;

        /// <summary>
        /// The value to match the field against.
        /// </summary>
        public FWP_CONDITION_VALUE0 ConditionValue;

        /// <summary>
        /// Protocol family used by the RPC endpoint.
        /// </summary>
        public RpcProtocolSequence? Protocol
        {
            get
            {
                if (this.FieldKey == PInvoke.FWPM_CONDITION_RPC_PROTOCOL)
                {
                    return (RpcProtocolSequence?)this.ConditionValue.UInt8Value;
                }
                else
                {
                    return null;
                }
            }
        }

        /// <summary>
        /// The authentication level controls how much security a client or server wants from its SSP.
        /// </summary>
        public RpcAuthenticationLevel? AuthenticationLevel
        {
            get
            {
                if (this.FieldKey == PInvoke.FWPM_CONDITION_RPC_AUTH_LEVEL)
                {
                    return (RpcAuthenticationLevel?)this.ConditionValue.UInt8Value;
                }
                else
                {
                    return null;
                }
            }
        }

        /// <summary>
        /// Authentication service used for RPC connections.
        /// </summary>
        public RpcAuthenticationType? AuthenticationType
        {
            get
            {
                if (this.FieldKey == PInvoke.FWPM_CONDITION_RPC_AUTH_TYPE)
                {
                    return (RpcAuthenticationType?)this.ConditionValue.UInt8Value;
                }
                else
                {
                    return null;
                }
            }
        }

        /// <summary>
        /// The remote IP address. 
        /// </summary>
        public IPAddress? RemoteAddress
        {
            get
            {
                if (this.FieldKey == PInvoke.FWPM_CONDITION_IP_REMOTE_ADDRESS_V4)
                {
                    if ( this.ConditionValue.Type == FWP_DATA_TYPE.FWP_UINT32)
                    {
                        return new IPAddress(this.ConditionValue.Value.int32);
                    }
                    else if(this.ConditionValue.Type == FWP_DATA_TYPE.FWP_V4_ADDR_MASK)
                    {
                        // TODO: Parse the mask
                        return null;
                    }
                    else
                    {
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
                        // TODO: Parse the IPv6 address mask
                        return null;
                    }
                    else
                    {
                        return null;
                    }
                }
                else
                {
                    return null;
                }
            }
        }

        /// <summary>
        /// The local transport protocol port number.
        /// </summary>
        public ushort? LocalPort
        {
            get
            {
                if (this.FieldKey == PInvoke.FWPM_CONDITION_IP_LOCAL_PORT)
                {
                    return this.ConditionValue.UInt16Value;
                }
                else
                {
                    return null;
                }
            }
        }
        // FWPM_CONDITION_REMOTE_USER_TOKEN
        /*
         *  	The identification of the remote user.
        Data type: FWP_SECURITY_DESCRIPTOR_TYPE*/

        /// <summary>
        /// The identification of the COM application.
        /// </summary>
        public Guid? DcomAppId
        {
            get
            {
                if (this.FieldKey == PInvoke.FWPM_CONDITION_DCOM_APP_ID)
                {
                    return this.ConditionValue.GuidValue;
                }
                else
                {
                    return null;
                }
            }
        }

        // FWPM_CONDITION_IMAGE_NAME

        /* 	The name of the application.
        Data type: FWP_BYTE_BLOB_TYPE
        */

        /// <summary>
        /// The UUID of the RPC interface.
        /// </summary>
        public Guid? InterfaceUUID
        {
            get
            {
                if (this.FieldKey == PInvoke.FWPM_CONDITION_RPC_IF_UUID)
                {
                    return this.ConditionValue.GuidValue;
                }
                else
                {
                    return null;
                }
            }
        }
        /// <summary>
        /// The version of the RPC interface.
        /// </summary>
        public ushort? InterfaceVersion
        {
            get
            {
                if (this.FieldKey == PInvoke.FWPM_CONDITION_RPC_IF_VERSION)
                {
                    return this.ConditionValue.UInt16Value;
                }
                else
                {
                    return null;
                }
            }
        }

        /// <summary>
        /// Reserved for internal use.
        /// </summary>
        public uint? InterfaceFlag
        {
            get
            {
                if (this.FieldKey == PInvoke.FWPM_CONDITION_RPC_IF_FLAG)
                {
                    return this.ConditionValue.UInt32Value;
                }
                else
                {
                    return null;
                }
            }
        }

        public ushort? OperationNumber
        {
            get
            {
                // TODO: Use the FWPM_CONDITION_RPC_OPNUM constant once it gets into the API.
                if (this.FieldKey == Guid.Parse("d58efb76-aab7-4148-a87e-9581134129b9"))
                {
                    return this.ConditionValue.UInt16Value;
                }
                else
                {
                    return null;
                }
            }
        }

        public string? NamedPipe
        {
            get
            {
                /*
                 * FWPM_CONDITION_PIPE

	The name of the remote named pipe.
Data type: FWP_BYTE_BLOB_TYPE
                 * */
                return null;
            }
        }

        public SecurityIdentifier? Principal
        {
            get
            {
                return null;
            }
        }
    }
}
