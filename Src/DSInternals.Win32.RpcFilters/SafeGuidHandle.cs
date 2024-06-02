using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace DSInternals.Win32.RpcFilters
{
    internal class SafeGuidHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeGuidHandle(IntPtr handle) : base(false)
        {
            // The value was allocated by someone else.
            this.handle = handle;
        }

        public SafeGuidHandle(Guid? identifier) : base(true)
        {
            if (identifier.HasValue)
            {
                // Copy the Guid to unmanaged memory
                Marshal.StructureToPtr<Guid>(identifier.Value, this.handle, false);
            }
        }

        public Guid? Value => this.IsInvalid ? null : Marshal.PtrToStructure<Guid>(this.handle);

        protected override bool ReleaseHandle()
        {
            Marshal.DestroyStructure<Guid>(handle);
            return true;
        }
    }
}
