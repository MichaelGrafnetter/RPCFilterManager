using System.Runtime.InteropServices;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Stores an array containing a variable number of bytes.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal readonly struct FWP_BYTE_BLOB_PTR
{
    /// <summary>
    /// Number of bytes in the array.
    /// </summary>
    private readonly uint size;

    /// <summary>
    /// Pointer to the array.
    /// </summary>
    private readonly IntPtr data;

    public readonly byte[]? BinaryData
    {
        get
        {
            if (this.size == 0 || this.data == IntPtr.Zero)
            {
                return null;
            }

            byte[] array = new byte[this.size];
            Marshal.Copy(this.data, array, 0, (int)this.size);
            return array;
        }
    }

    public readonly string? StringData
    {
        get
        {
            if (size % sizeof(char) != 0 || size < sizeof(char))
            {
                // This cannot be a unicode string, as the data has odd number of bytes.
                return null;
            }

            // Remove the trailing \0
            // TODO: Check if the string actually ends with \0 in UTF-16
            int expectedStringLength = (int)size / sizeof(char) - 1;

            // PtrToStringUni contains a null pointer check.
            return Marshal.PtrToStringUni(this.data);
        }
    }

    public FWP_BYTE_BLOB_PTR(SafeByteArrayHandle data, uint size)
    {
        if (data != null && size > 0)
        {
            this.data = data.DangerousGetHandle();
            this.size = size;
        }
    }
}

/// <summary>
/// Stores an array containing a variable number of bytes.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal readonly struct FWP_BYTE_BLOB_STRING
{
    /// <summary>
    /// Number of bytes in the array.
    /// </summary>
    private readonly uint size;

    /// <summary>
    /// Pointer to the array.
    /// </summary>
    [MarshalAs(UnmanagedType.LPWStr)]
    private readonly string? Data;

    public FWP_BYTE_BLOB_STRING(string value)
    {
        if (value != null)
        {
            this.size = (uint)(sizeof(char) * (value.Length + 1));
            this.Data = value;
        }
    }
}
