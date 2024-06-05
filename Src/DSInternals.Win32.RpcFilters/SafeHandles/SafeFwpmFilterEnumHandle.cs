using Microsoft.Win32.SafeHandles;
using Windows.Win32.Foundation;

namespace DSInternals.Win32.RpcFilters
{
    internal class SafeFwpmFilterEnumHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeFwpmEngineHandle engineHandle;

        internal SafeFwpmFilterEnumHandle(SafeFwpmEngineHandle engineHandle, HANDLE enumHandle) : base(true)
        {
            this.handle = enumHandle;
            this.engineHandle = engineHandle;
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.FwpmFilterDestroyEnumHandle0(this.engineHandle, (HANDLE)this.handle) == WIN32_ERROR.ERROR_SUCCESS;
        }
    }
}
