using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32.SafeHandles;

namespace DSInternals.Win32.RpcFilters;

internal sealed class SafeUnicodeSecureStringPointer : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeUnicodeSecureStringPointer(SecureString password)
        : base(true)
    {
        if (password != null)
        {
            IntPtr pointer = Marshal.SecureStringToGlobalAllocUnicode(password);
            this.SetHandle(pointer);
        }
    }

    public SafeUnicodeSecureStringPointer(byte[] password)
        : base(true)
    {
        if (password != null)
        {
            if (password.Length % sizeof(char) == 1)
            {
                // Unicode strings must have even number of bytes
                throw new FormatException(nameof(password));
            }

            IntPtr buffer = Marshal.AllocHGlobal(password.Length + sizeof(char));
            Marshal.Copy(password, 0, buffer, password.Length);

            // Add the trailing zero
            Marshal.WriteInt16(buffer, password.Length, 0);

            this.SetHandle(buffer);
        }
    }

    protected override bool ReleaseHandle()
    {
        Marshal.ZeroFreeGlobalAllocUnicode(handle);
        return true;
    }

    public override string? ToString()
    {
        return Marshal.PtrToStringUni(this.handle);
    }
}
