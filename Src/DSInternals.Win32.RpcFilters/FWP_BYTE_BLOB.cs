using System.Runtime.InteropServices;

namespace DSInternals.Win32.RpcFilters
{
    /// <summary>
    /// Stores an array containing a variable number of bytes.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_BYTE_BLOB
    {
        /// <summary>
        /// Number of bytes in the array.
        /// </summary>
        public uint Size;

        /// <summary>
        /// Pointer to the array.
        /// </summary>
        public IntPtr Data;
    }
}
