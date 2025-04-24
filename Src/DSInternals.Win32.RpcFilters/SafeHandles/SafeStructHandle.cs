using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace DSInternals.Win32.RpcFilters;

internal sealed class SafeStructHandle<T> : SafeHandleZeroOrMinusOneIsInvalid where T : struct
{
    private SafeStructHandle(IntPtr handle) : base(false)
    {
        // The value was allocated by someone else.
        this.handle = handle;
    }

    public SafeStructHandle(T value) : base(true)
    {
        // Copy the struct to unmanaged memory
        this.handle = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
        Marshal.StructureToPtr<T>(value, this.handle, false);
    }

    public T? Value => this.IsInvalid ? null : Marshal.PtrToStructure<T>(this.handle);

    protected override bool ReleaseHandle()
    {
        Marshal.DestroyStructure<T>(handle);
        return true;
    }
}

