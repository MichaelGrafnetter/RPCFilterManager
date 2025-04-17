using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace DSInternals.Win32.RpcFilters;

internal class SafeByteArrayHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeByteArrayHandle(byte[] value) : base(true)
    {
        if(value == null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        this.handle = Marshal.AllocHGlobal(value.Length);
        GCHandle pinnedArray = GCHandle.Alloc(value, GCHandleType.Pinned);

        try
        {
            Marshal.Copy(value, 0, this.handle, value.Length);
        }
        finally
        {
            pinnedArray.Free();
        }
    }

    protected override bool ReleaseHandle()
    {
        Marshal.FreeHGlobal(this.handle);
        return true;
    }
}
