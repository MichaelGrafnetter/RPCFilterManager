using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DSInternals.Win32.RpcFilters;

internal sealed class SafeUnicodeStringPointer : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeUnicodeStringPointer(string? value)
        : base(true)
    {
        IntPtr pointer = Marshal.StringToHGlobalUni(value);
        this.SetHandle(pointer);
    }

    protected override bool ReleaseHandle()
    {
        Marshal.FreeHGlobal(handle);
        return true;
    }

    public override string? ToString()
    {
        return Marshal.PtrToStringUni(this.handle);
    }
}
