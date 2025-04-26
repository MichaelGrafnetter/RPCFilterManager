using System.ComponentModel;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Manages RPC filters in the Windows Filtering Platform (WFP).
/// </summary>
public sealed class RpcFilterManager : IDisposable
{
    private const int DefaultWaitTimeoutInMSec = 10000;
    private const uint FilterEnumBatchSize = 100;

    /// <summary>
    /// The RPC OpNum for an RPC call made to an RPC listener.
    /// </summary>
    // TODO: [Obsolete("Switch to the FWPM_CONDITION_RPC_OPNUM system constant once it gets into the API.")]
    internal static readonly Guid FWPM_CONDITION_RPC_OPNUM = Guid.Parse("d58efb76-aab7-4148-a87e-9581134129b9");

    private SafeFwpmEngineHandle? engineHandle;

    // TODO: The documentation is incorrect. The FWPM_CONDITION_RPC_OPNUM filter condition has been backported to downlevel Windows versions.
    /// <summary>
    /// Indicates whether the RPC OpNum filter condition is supported on the current operating system.
    /// </summary>
    /// <remarks>The FWPM_CONDITION_RPC_OPNUM filter condition is supported since Windows 11 24H2 (10.0.26100).</remarks>
    public static bool IsOpnumFilterSupported => Environment.OSVersion.Version >= new Version(10, 0, 26100);

    /// <summary>
    /// Opens a session to the filter engine.
    /// </summary>
    public RpcFilterManager()
    {
        var session = new FWPM_SESSION0
        {
            TxnWaitTimeoutInMSec = DefaultWaitTimeoutInMSec
        };

        WIN32_ERROR result = NativeMethods.FwpmEngineOpen0(null, RpcAuthenticationType.Default, null, session, out this.engineHandle);
        ValidateResult(result);
    }

    /// <summary>
    /// Retrieves a list of RPC filters from the system.
    /// </summary>
    /// <param name="providerKey">Unique identifier of the provider associated with the filters to be returned.</param>
    /// <returns>List of RPC filters.</returns>
    /// <exception cref="InvalidOperationException"></exception>
    public IEnumerable<RpcFilter> GetFilters(Guid? providerKey = null)
    {
        if (this.engineHandle == null || this.engineHandle.IsInvalid)
        {
            throw new InvalidOperationException("The filter engine handle is invalid.");
        }

        var enumTemplate = new FWPM_FILTER_ENUM_TEMPLATE0()
        {
            ProviderKey = providerKey,
            LayerKey = PInvoke.FWPM_LAYER_RPC_UM,
            EnumType = FWP_FILTER_ENUM_TYPE.FWP_FILTER_ENUM_OVERLAPPING,
            Flags = FWP_FILTER_ENUM_FLAGS.FWP_FILTER_ENUM_FLAG_SORTED | FWP_FILTER_ENUM_FLAGS.FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
            // Ignore the filter's action type when enumerating. 
            ActionMask = (FWP_ACTION_TYPE)uint.MaxValue
        };

        var result = NativeMethods.FwpmFilterCreateEnumHandle0(this.engineHandle, enumTemplate, out SafeFwpmFilterEnumHandle enumHandle);

        try
        {
            ValidateResult(result);

            uint numReturned = 0;
            SafeFwpmBuffer? entries = null;

            do
            {
                try
                {
                    var result2 = NativeMethods.FwpmFilterEnum0(this.engineHandle, enumHandle, FilterEnumBatchSize, out entries, out numReturned);
                    ValidateResult(result2);

                    if(numReturned == 0 || entries == null)
                    {
                        break;
                    }

                    IntPtr[] entryPointers = new IntPtr[numReturned];
                    entries.Initialize<IntPtr>(numReturned);
                    entries.ReadArray<IntPtr>(0, entryPointers, 0, (int)numReturned);

                    foreach(var entryPointer in entryPointers)
                    {
                        if(entryPointer == IntPtr.Zero)
                        {
                            continue;
                        }

                        var nativeFilter = Marshal.PtrToStructure<FWPM_FILTER0>(entryPointer);
                        var filter = RpcFilter.Create(nativeFilter);
                        yield return filter;
                    }
                }
                finally
                {
                    // Free the memory
                    entries?.Dispose();
                }
            } while(true);
        }
        finally
        {
            // Ignore any errors during cleanup.
            enumHandle.Dispose();
        }
    }

    // TODO: Add additional exceptions for specific error codes.

    /// <summary>
    /// Adds a new filter object to the system.
    /// </summary>
    /// <param name="filter">The filter object to be added.</param>
    /// <returns>The runtime identifier for the newly created filter.</returns>
    /// <exception cref="InvalidOperationException"></exception>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    /// <exception cref="PlatformNotSupportedException"></exception>
    public ulong AddFilter(RpcFilter filter)
    {
        if (this.engineHandle == null || this.engineHandle.IsInvalid)
        {
            throw new InvalidOperationException("The filter engine handle is invalid.");
        }

        if (filter == null)
        {
            throw new ArgumentNullException(nameof(filter));
        }

        // Weight must be in the range [0, 15]
        if (filter.Weight.HasValue && filter.Weight.Value > 15)
        {
            throw new ArgumentOutOfRangeException(nameof(filter.Weight), filter.Weight.Value, "The weight must be in the range [0, 15].");
        }

        FWP_VALUE0 nativeWeight = filter.Weight.HasValue ? new FWP_VALUE0((byte)filter.Weight.Value) : new FWP_VALUE0();
        Guid subLayer = filter.Audit ? PInvoke.FWPM_SUBLAYER_RPC_AUDIT : PInvoke.FWPM_SUBLAYER_UNIVERSAL;
        FWPM_ACTION0 action = new(filter.Action);
        FWPM_FILTER_FLAGS flags = FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_NONE;

        if(filter.IsPersistent)
        {
            flags |= FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_PERSISTENT;
        }

        if(filter.IsBootTimeEnforced)
        {
            flags |= FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_BOOTTIME;
        }

        var conditions = new List<FWPM_FILTER_CONDITION0>();
        var handles = new Stack<SafeHandle>();

        if(filter.AuthenticationLevel.HasValue)
        {
            conditions.Add(new FWPM_FILTER_CONDITION0(filter.AuthenticationLevel.Value));
        }
        if(filter.AuthenticationType.HasValue)
        {
            conditions.Add(new FWPM_FILTER_CONDITION0(filter.AuthenticationType.Value));
        }
        if (filter.Protocol.HasValue)
        {
            conditions.Add(new FWPM_FILTER_CONDITION0(filter.Protocol.Value));
        }
        
        if (filter.LocalPort.HasValue)
        {
            conditions.Add(new FWPM_FILTER_CONDITION0(PInvoke.FWPM_CONDITION_IP_LOCAL_PORT, filter.LocalPort.Value));
        }
        if (filter.InterfaceVersion.HasValue)
        {
            conditions.Add(new FWPM_FILTER_CONDITION0(PInvoke.FWPM_CONDITION_RPC_IF_VERSION, filter.InterfaceVersion.Value));
        }
        if (filter.InterfaceFlag.HasValue)
        {
            conditions.Add(new FWPM_FILTER_CONDITION0(filter.InterfaceFlag.Value));
        }
        
        if (filter.InterfaceUUID.HasValue)
        {
            (var condition, var handle) = FWPM_FILTER_CONDITION0.Create(PInvoke.FWPM_CONDITION_RPC_IF_UUID, filter.InterfaceUUID.Value);
            handles.Push(handle);
            conditions.Add(condition);
        }

        if (filter.DcomAppId.HasValue)
        {
            (var condition, var handle) = FWPM_FILTER_CONDITION0.Create(PInvoke.FWPM_CONDITION_DCOM_APP_ID, filter.DcomAppId.Value);
            handles.Push(handle);
            conditions.Add(condition);
        }
        if (filter.OperationNumber.HasValue)
        {
            // This filter condition is not supported on older OS version.
            conditions.Add(new FWPM_FILTER_CONDITION0(RpcFilterManager.FWPM_CONDITION_RPC_OPNUM, filter.OperationNumber.Value));
        }
        
        if (filter.NamedPipe != null)
        {
            (var condition, var handle) = FWPM_FILTER_CONDITION0.Create(PInvoke.FWPM_CONDITION_PIPE, filter.NamedPipe);
            handles.Push(handle);
            conditions.Add(condition);
        }

        if (filter.ImageName != null)
        {
            (var condition, var handle) = FWPM_FILTER_CONDITION0.Create(PInvoke.FWPM_CONDITION_IMAGE_NAME, filter.ImageName);
            handles.Push(handle);
            conditions.Add(condition);
        }

        if (filter.SecurityDescriptor != null)
        {
            (var condition, var handle1, var handle2) = FWPM_FILTER_CONDITION0.Create(filter.SecurityDescriptor);
            handles.Push(handle1);
            handles.Push(handle2);
            conditions.Add(condition);
        }

        if (filter.LocalAddress != null)
        {
            (var condition, var handle) = FWPM_FILTER_CONDITION0.Create(filter.LocalAddress, filter.LocalAddressMask, false);

            if (handle != null)
            {
                handles.Push(handle);
            }

            conditions.Add(condition);
        }

        if (filter.RemoteAddress != null)
        {
            (var condition, var handle) = FWPM_FILTER_CONDITION0.Create(filter.RemoteAddress, filter.RemoteAddressMask, true);

            if (handle != null)
            {
                handles.Push(handle);
            }

            conditions.Add(condition);
        }

        var nativeFilter = new FWPM_FILTER0()
        {
            LayerKey = PInvoke.FWPM_LAYER_RPC_UM,
            SubLayerKey = subLayer,
            Weight = nativeWeight,
            Action = action,
            DisplayData = new FWPM_DISPLAY_DATA0(filter.Name, filter.Description),
            FilterKey = filter.FilterKey,
            Flags = flags
        };

        var conditionsHandle = new GCHandle();

        if(conditions.Count > 0)
        {
            conditionsHandle = nativeFilter.SetFilterConditions(conditions);
        }

        WIN32_ERROR result = NativeMethods.FwpmFilterAdd0(this.engineHandle, nativeFilter, IntPtr.Zero, out ulong id);
        ValidateResult(result);


        // Free the memory
        // TODO: Free in a safer way
        conditionsHandle.Free();

        foreach(var handle in handles)
        {
            handle.Dispose();
        }

        // Augment the input object with the runtime identifier.
        filter.FilterId = id;

        return id;
    }

    /// <summary>
    /// Removes a filter object from the system.
    /// </summary>
    /// <param name="id">Runtime identifier for the object being removed from the system.</param>
    /// <exception cref="InvalidOperationException"></exception>
    public void RemoveFilter(ulong id)
    {
        if (this.engineHandle == null || this.engineHandle.IsInvalid)
        {
            throw new InvalidOperationException("The filter engine handle is invalid.");
        }

        WIN32_ERROR result = NativeMethods.FwpmFilterDeleteById0(this.engineHandle, id);
        ValidateResult(result);
    }

    /// <summary>
    /// Closes the session to the filter engine.
    /// </summary>
    public void Dispose()
    {
        this.engineHandle?.Dispose();
        this.engineHandle = null;
        GC.SuppressFinalize(this);
    }

    private static void ValidateResult(WIN32_ERROR code)
    {
        if(code == WIN32_ERROR.ERROR_SUCCESS)
        {
            return;
        }

        var genericException = new Win32Exception((int)code);
        Exception exceptionToThrow = code switch
        {
            WIN32_ERROR.ERROR_INVALID_PARAMETER => new ArgumentException(genericException.Message, genericException),
            WIN32_ERROR.ERROR_ACCESS_DENIED => new UnauthorizedAccessException(genericException.Message, genericException),
            WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY or WIN32_ERROR.ERROR_OUTOFMEMORY => new OutOfMemoryException(genericException.Message, genericException),
            // TODO: Handle HRESULT.FWP_E_FILTER_NOT_FOUND
            // TODO: Handle HRESULT.FWP_E_ALREADY_EXISTS
            // TODO: Handle RPC_STATUS.RPC_S_SERVER_UNAVAILABLE.
            // TODO: Handle FWP_E_INVALID_NET_MASK
            // TODO: Handle FWP_E_CONDITION_NOT_FOUND => PlatformNotSupportedException
            // TODO: FWP_E_FILTER_NOT_FOUND
            // TODO: Handle FWP_E_INVALID_WEIGHT
            _ => genericException,
            // We were not able to translate the Win32Exception to a more specific type.
        };
        throw exceptionToThrow;
    }
}
