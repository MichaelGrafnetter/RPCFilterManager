using Windows.Win32;

namespace DSInternals.Win32.RpcFilters
{
    /// <summary>
    /// Authentication service used for RPC connections.
    /// </summary>
    public enum RPC_C_AUTHN : uint
    {
        /// <summary>
        /// Use the default authentication service.
        /// </summary>
        RPC_C_AUTHN_DEFAULT = unchecked((uint)PInvoke.RPC_C_AUTHN_DEFAULT),

        /// <summary>
        /// Use the Microsoft NT LAN Manager (NTLM) SSP.
        /// </summary>
        RPC_C_AUTHN_WINNT = PInvoke.RPC_C_AUTHN_WINNT,
    }
}
