namespace DSInternals.Win32.RpcFilters
{
    /// <summary>
    /// Settings to control session behavior.
    /// </summary>
    [Flags]
    internal enum FWPM_SESSION_FLAGS : uint
    {
        None = 0,

        /// <summary>
        /// When this flag is set, any objects added during the session are automatically deleted when the session ends. 
        /// </summary>
        FWPM_SESSION_FLAG_DYNAMIC = Windows.Win32.PInvoke.FWPM_SESSION_FLAG_DYNAMIC,

        /// <summary>
        /// Reserved.
        /// </summary>
        FWPM_SESSION_FLAG_RESERVED = Windows.Win32.PInvoke.FWPM_SESSION_FLAG_RESERVED
    }
}
