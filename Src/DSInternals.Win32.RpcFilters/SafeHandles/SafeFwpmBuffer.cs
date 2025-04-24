using System.Runtime.InteropServices;

namespace DSInternals.Win32.RpcFilters;

internal sealed class SafeFwpmBuffer : SafeBuffer
{
    internal SafeFwpmBuffer()
        : base(true)
    {
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.FwpmFreeMemory0(ref handle);
        return true;
    }
}
