using System.ComponentModel;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace DSInternals.Win32.RpcFilters
{
    public class RpcFilterManager : IDisposable
    {
        private const int DefaultWaitTimeoutInMSec = 10000;
        private const uint FilterEnumBatchSize = 100;

        private SafeFwpmEngineHandle? engineHandle;

        public RpcFilterManager()
        {
            var session = new FWPM_SESSION0
            {
                TxnWaitTimeoutInMSec = DefaultWaitTimeoutInMSec
            };

            WIN32_ERROR result = NativeMethods.FwpmEngineOpen0(null, RpcAuthenticationType.Default, null, session, out this.engineHandle);
            ValidateResult(result);
        }

        public IList<RpcFilter> GetFilters(Guid? providerKey = null)
        {
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
                var filters = new List<RpcFilter>();

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
                            filters.Add(filter);
                        }
                    }
                    finally
                    {
                        // Free the memory
                        entries?.Dispose();
                    }
                } while(true);

                return filters;
            }
            finally
            {
                // Ignore any errors during cleanup.
                enumHandle.Dispose();
            }
        }

        public ulong AddFilter(RpcFilter filter)
        {
            if(filter == null)
            {
                throw new ArgumentNullException(nameof(filter));
            }

            // Weight must be in the range [0, 15]
            if(filter.Weight.HasValue && filter.Weight.Value > 15)
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

            

            var nativeFilter = new FWPM_FILTER0()
            {
                LayerKey = PInvoke.FWPM_LAYER_RPC_UM,
                SubLayerKey = subLayer,
                Weight = nativeWeight,
                Action = action,
                DisplayData = new FWPM_DISPLAY_DATA0(filter.Name, filter.Description),
                FilterKey = filter.FilterKey,
                Flags = flags,
                //NumFilterConditions = 0,
                // FilterCondition
            };

            WIN32_ERROR result = NativeMethods.FwpmFilterAdd0(this.engineHandle, nativeFilter, null, out ulong id);
            ValidateResult(result);
            
            return id;
        }

        public void RemoveFilter(ulong id)
        {
            WIN32_ERROR result = NativeMethods.FwpmFilterDeleteById0(this.engineHandle, id);
            ValidateResult(result);
        }

        public void Dispose()
        {
            this.engineHandle?.Dispose();
            this.engineHandle = null;
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
                _ => genericException,
                // TODO: Handle RPC_STATUS.RPC_S_SERVER_UNAVAILABLE.
                // We were not able to translate the Win32Exception to a more specific type.
            };
            throw exceptionToThrow;
        }
    }
}
