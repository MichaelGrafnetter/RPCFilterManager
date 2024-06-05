using System.Runtime.InteropServices;

namespace DSInternals.Win32.RpcFilters
{
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

        public readonly byte[]? Data
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
    }

    /// <summary>
    /// Stores an array containing a variable number of bytes.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct FWP_BYTE_BLOB
    {
        /// <summary>
        /// Number of bytes in the array.
        /// </summary>
        private readonly uint size;

        /// <summary>
        /// Pointer to the array.
        /// </summary>
        public readonly byte[] Data;

        public FWP_BYTE_BLOB(byte[] data)
        {
            if(data != null)
            {
                this.size = (uint)data.Length;
                this.Data = data;
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
            if(value != null)
            {
                this.size = (uint)(sizeof(char)*(value.Length + 1));
                this.Data = value;
            }
        }
    }
}
