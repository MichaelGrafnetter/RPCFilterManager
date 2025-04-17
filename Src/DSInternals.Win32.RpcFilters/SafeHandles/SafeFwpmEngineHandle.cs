using Microsoft.Win32.SafeHandles;
using Windows.Win32.Foundation;

namespace DSInternals.Win32.RpcFilters;

internal class SafeFwpmEngineHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeFwpmEngineHandle() : base(true)
    {
    }

    protected override bool ReleaseHandle()
    {
        return NativeMethods.FwpmEngineClose0(this.handle) == WIN32_ERROR.ERROR_SUCCESS;
    }
}
