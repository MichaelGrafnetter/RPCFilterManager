#pragma warning disable CA1028 // Enum Storage should be Int32

using Windows.Win32.System.Com;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// The authentication level controls how much security a client or server wants from its SSP.
/// </summary>
public enum RpcAuthenticationLevel : uint
{
    /// <summary>
    /// No authentication is performed during the communication between client and server.
    /// </summary>
    None = RPC_C_AUTHN_LEVEL.RPC_C_AUTHN_LEVEL_NONE,

    /// <summary>
    /// COM chooses the authentication level by using its normal security blanket negotiation.
    /// </summary>
    Default = RPC_C_AUTHN_LEVEL.RPC_C_AUTHN_LEVEL_DEFAULT,

    /// <summary>
    /// The normal authentication handshake occurs between the client and server, and a session key is established but that key is never used for communication between the client and server.
    /// </summary>
    Connect = RPC_C_AUTHN_LEVEL.RPC_C_AUTHN_LEVEL_CONNECT,

    /// <summary>
    /// Only the headers of the beginning of each call are signed.
    /// </summary>
    Call = RPC_C_AUTHN_LEVEL.RPC_C_AUTHN_LEVEL_CALL,

    /// <summary>
    /// The header of each packet is signed but not encrypted.
    /// </summary>
    Packet = RPC_C_AUTHN_LEVEL.RPC_C_AUTHN_LEVEL_PKT,

    /// <summary>
    /// Each packet of data is signed in its entirety but is not encrypted.
    /// </summary>
    PacketIntegrity = RPC_C_AUTHN_LEVEL.RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,

    /// <summary>
    /// Each data packet is signed and encrypted.
    /// </summary>
    PacketPrivacy = RPC_C_AUTHN_LEVEL.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
}
