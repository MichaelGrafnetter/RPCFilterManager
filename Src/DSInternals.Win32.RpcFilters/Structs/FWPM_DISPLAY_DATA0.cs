using System.Runtime.InteropServices;

namespace DSInternals.Win32.RpcFilters
{
    /// <summary>
    /// Stores an optional friendly name and an optional description for an object.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct FWPM_DISPLAY_DATA0
    {
        /// <summary>
        /// Optional friendly name.
        /// </summary>
        public string? Name;

        /// <summary>
        /// Optional description.
        /// </summary>
        public string? Description;

        public FWPM_DISPLAY_DATA0(string? name, string? description)
        {
            Name = name;
            Description = description;
        }
    }
}
