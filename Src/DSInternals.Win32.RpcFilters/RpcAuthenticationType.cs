using Windows.Win32;

namespace DSInternals.Win32.RpcFilters
{
    /// <summary>
    /// Authentication service used for RPC connections.
    /// </summary>
    public enum RpcAuthenticationType : uint
    {
        /// <summary>
        /// No authentication.
        /// </summary>
        None = PInvoke.RPC_C_AUTHN_NONE,

        /// <summary>
        /// Use the default authentication service.
        /// </summary>
        Default = unchecked((uint)PInvoke.RPC_C_AUTHN_DEFAULT),

        /// <summary>
        /// Use the Microsoft NT LAN Manager (NTLM) SSP.
        /// </summary>
        NTLM = PInvoke.RPC_C_AUTHN_WINNT,

        /// <summary>
        /// Use the Microsoft Negotiate SSP. This SSP negotiates between the use of the NTLM and Kerberos protocol Security Support Providers (SSP).
        /// </summary>
        Negotiate = PInvoke.RPC_C_AUTHN_GSS_NEGOTIATE,

        /// <summary>
        /// Use the Microsoft Kerberos SSP.
        /// </summary>
        Kerberos = PInvoke.RPC_C_AUTHN_GSS_KERBEROS,

        /// <summary>
        /// Use the Schannel SSP. This SSP supports Secure Socket Layer (SSL), private communication technology (PCT), and transport level security (TLS).
        /// </summary>
        SChannel = PInvoke.RPC_C_AUTHN_GSS_SCHANNEL,

        /// <summary>
        /// Use the Microsoft Digest SSP.
        /// </summary>
        Digest = PInvoke.RPC_C_AUTHN_DIGEST
    }
}
