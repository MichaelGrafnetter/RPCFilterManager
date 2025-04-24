using System.Runtime.InteropServices;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Stores the state associated with a client session.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal sealed class FWPM_SESSION0
{
    /// <summary>
    /// Uniquely identifies the session.
    /// </summary>
    public Guid SessionKey;

    /// <summary>
    /// Allows sessions to be annotated in a human-readable form.
    /// </summary>
    public FWPM_DISPLAY_DATA0 DisplayData;

    /// <summary>
    /// Settings to control session behavior.
    /// </summary>
    public FWPM_SESSION_FLAGS Flags;

    /// <summary>
    /// Time in milli-seconds that a client will wait to begin a transaction.
    /// </summary>
    public int TxnWaitTimeoutInMSec;

    /// <summary>
    /// Process ID of the client.
    /// </summary>
    public int ProcessId;

    /// <summary>
    /// SID of the client.
    /// </summary>
    public byte[]? Sid;

    /// <summary>
    /// User name of the client.
    /// </summary>
    [MarshalAs(UnmanagedType.LPWStr)]
    public string? Username;

    /// <summary>
    /// TRUE if this is a kernel-mode client.
    /// </summary>
    [MarshalAs(UnmanagedType.Bool)]
    public bool KernelMode;
}
