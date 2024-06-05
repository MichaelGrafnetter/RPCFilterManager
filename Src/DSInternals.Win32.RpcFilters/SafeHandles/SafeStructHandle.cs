using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace DSInternals.Win32.RpcFilters
{
    internal class SafeStructHandle<T> : SafeHandleZeroOrMinusOneIsInvalid where T : struct
    {
        private SafeStructHandle(IntPtr handle) : base(false)
        {
            // The value was allocated by someone else.
            this.handle = handle;
        }

        public SafeStructHandle(T value) : base(true)
        {
            // Copy the Guid to unmanaged memory
            Marshal.StructureToPtr<T>(value, this.handle, false);
        }

        public T? Value => this.IsInvalid ? null : Marshal.PtrToStructure<T>(this.handle);

        protected override bool ReleaseHandle()
        {
            Marshal.DestroyStructure<T>(handle);
            return true;
        }
    }
 }
