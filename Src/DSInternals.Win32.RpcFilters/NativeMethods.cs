using System.Runtime.InteropServices;
using Windows.Win32.Foundation;

namespace DSInternals.Win32.RpcFilters
{

    internal class NativeMethods
    {
        private const string FwpuClnt = "Fwpuclnt.dll";

        /// <summary>
        /// Opens a session to the filter engine.
        /// </summary>
        /// <param name="serverName">This value must be NULL.</param>
        /// <param name="authnService">Specifies the authentication service to use.</param>
        /// <param name="authIdentity">The authentication and authorization credentials for accessing the filter engine.</param>
        /// <param name="session">Session-specific parameters for the session being opened.</param>
        /// <param name="engineHandle">Handle for the open session to the filter engine.</param>
        /// <returns>Code indicating whether the session was started successfully.</returns>
        [DllImport(FwpuClnt, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern WIN32_ERROR FwpmEngineOpen0(
            string? serverName,
            RPC_C_AUTHN authnService,
            SEC_WINNT_AUTH_IDENTITY_W? authIdentity,
            FWPM_SESSION0? session,
            out SafeFwpmEngineHandle engineHandle
        );

        /// <summary>
        /// Closes a session to a filter engine.
        /// </summary>
        /// <param name="engineHandle">Handle for an open session to the filter engine.</param>
        /// <returns>Code indicating whether the session was closed successfully.</returns>
        [DllImport(FwpuClnt)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern WIN32_ERROR FwpmEngineClose0(IntPtr engineHandle);

        /// <summary>
        /// Creates a handle used to enumerate a set of filter objects.
        /// </summary>
        /// <param name="engineHandle">Handle for an open session to the filter engine.</param>
        /// <param name="enumTemplate">Template to selectively restrict the enumeration.</param>
        /// <param name="enumHandle">The handle for filter enumeration.</param>
        /// <returns>Code indicating whether the enumerator was created successfully. </returns>
        [DllImport(FwpuClnt, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern WIN32_ERROR FwpmFilterCreateEnumHandle0(
            SafeFwpmEngineHandle engineHandle,
            [MarshalAs(UnmanagedType.LPStruct)]
            FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate,
            out HANDLE enumHandle
        );

        /// <summary>
        /// Returns the next page of results from the filter enumerator.
        /// </summary>
        /// <param name="engineHandle">Handle for an open session to the filter engine.</param>
        /// <param name="enumHandle">Handle for a filter enumeration.</param>
        /// <param name="numEntriesRequested">The number of filter objects requested.</param>
        /// <param name="entries">Addresses of enumeration entries.</param>
        /// <param name="numEntriesReturned">The number of filter objects returned.</param>
        /// <returns>Code indicating whether the filters were enumerated successfully. </returns>
        [DllImport(FwpuClnt, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern WIN32_ERROR FwpmFilterEnum0(
           SafeFwpmEngineHandle engineHandle,
           HANDLE enumHandle,
           uint numEntriesRequested,
           out SafeFwpmBuffer entries,
           out uint numEntriesReturned
        );

        /// <summary>
        /// Adds a new filter object to the system.
        /// </summary>
        /// <param name="engineHandle">Handle for an open session to the filter engine.</param>
        /// <param name="filter">The filter object to be added.</param>
        /// <param name="sd">Security information about the filter object.</param>
        /// <param name="id">The runtime identifier for this filter.</param>
        /// <returns>Code indicating whether the filter was successfully added.</returns>
        [DllImport(FwpuClnt, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern WIN32_ERROR FwpmFilterAdd0(
            SafeFwpmEngineHandle engineHandle,
            FWPM_FILTER0 filter,
            SafeBuffer? sd,
            out ulong id
        );

        /// <summary>
        /// Frees a filter enumeration handle.
        /// </summary>
        /// <param name="engineHandle">Handle for an open session to the filter engine.</param>
        /// <param name="enumHandle">Handle of a filter enumeration.</param>
        /// <returns>Code indicating whether the enumerator was successfully deleted.</returns>
        [DllImport(FwpuClnt)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern WIN32_ERROR FwpmFilterDestroyEnumHandle0(
            SafeFwpmEngineHandle engineHandle,
            HANDLE enumHandle
        );

        /// <summary>
        /// Removes a filter object from the system.
        /// </summary>
        /// <param name="engineHandle">Handle for an open session to the filter engine.</param>
        /// <param name="id">Runtime identifier for the object being removed from the system.</param>
        /// <returns>Code indicating whether the filter was successfully deleted.</returns>
        [DllImport(FwpuClnt)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern WIN32_ERROR FwpmFilterDeleteById0(
            SafeFwpmEngineHandle engineHandle,
            ulong id
        );

        /// <summary>
        /// Release memory resources allocated by the Windows Filtering Platform (WFP) functions.
        /// </summary>
        /// <param name="p">Address of the pointer to be freed.</param>
        [DllImport(FwpuClnt)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern void FwpmFreeMemory0(
            ref IntPtr p
        );
    }
}
