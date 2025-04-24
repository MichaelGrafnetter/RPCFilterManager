#pragma warning disable CA1707 // Identifiers should not contain underscores
#pragma warning disable CA1028 // Enum Storage should be Int32
#pragma warning disable CA1008 // Enums should have zero value

using Windows.Win32;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Microsoft RPC protocol sequences supported by the Windows Filtering Platform.
/// </summary>
public enum RpcProtocolSequence : uint
{
    /// <summary>
    /// Connection-oriented Transmission Control Protocol/Internet Protocol (TCP/IP).
    /// </summary>
    ncacn_ip_tcp = PInvoke.RPC_PROTSEQ_TCP,

    /// <summary>
    /// Connection-oriented named pipes.
    /// </summary>
    ncacn_np = PInvoke.RPC_PROTSEQ_NMP,

    /// <summary>
    /// Connection-oriented TCP/IP using Microsoft Internet Information Server as HTTP proxy.
    /// </summary>

    ncacn_http = PInvoke.RPC_PROTSEQ_HTTP,

    /// <summary>
    /// Local procedure call.
    /// </summary>
    ncalrpc = PInvoke.RPC_PROTSEQ_LRPC
}
