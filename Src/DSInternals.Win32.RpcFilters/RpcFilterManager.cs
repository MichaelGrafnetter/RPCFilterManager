using System.ComponentModel;
using System.Net;
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

        private SafeFwpmEngineHandle engineHandle;

        public RpcFilterManager()
        {
            var session = new FWPM_SESSION0();
            session.TxnWaitTimeoutInMSec = DefaultWaitTimeoutInMSec;

            WIN32_ERROR result = NativeMethods.FwpmEngineOpen0(null, RPC_C_AUTHN.RPC_C_AUTHN_DEFAULT, null, session, out this.engineHandle);
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
                ActionMask = FWP_ACTION_TYPE.FWP_ACTION_PERMIT | FWP_ACTION_TYPE.FWP_ACTION_BLOCK | FWP_ACTION_TYPE.FWP_ACTION_CONTINUE
            };

            WIN32_ERROR result = NativeMethods.FwpmFilterCreateEnumHandle0(this.engineHandle, enumTemplate, out HANDLE enumHandle);

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
                        WIN32_ERROR result2 = NativeMethods.FwpmFilterEnum0(this.engineHandle, enumHandle, FilterEnumBatchSize, out entries, out numReturned);
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
                NativeMethods.FwpmFilterDestroyEnumHandle0(this.engineHandle, enumHandle);
            }
        }

        ulong AddTcpFilter(
            string name,
            string description,
            Guid? filterKey,
            Guid interfaceUUID,
            bool permit,
            int? operationNumber,
            byte? weight,
            IPAddress? remoteAddress,
            bool audit = false

            )
        {
            // Weight must be in the range [0, 15]
            FWP_VALUE0 nativeWeight = weight.HasValue ? new FWP_VALUE0(weight.Value) : new FWP_VALUE0();
            Guid subLayer = audit ? PInvoke.FWPM_SUBLAYER_RPC_AUDIT : PInvoke.FWPM_SUBLAYER_UNIVERSAL;
            FWPM_ACTION0 action = new FWPM_ACTION0(permit);
            filterKey ??= Guid.NewGuid();

            var filter = new FWPM_FILTER0()
            {
                LayerKey = PInvoke.FWPM_LAYER_RPC_UM,
                SubLayerKey = subLayer,
                Weight = nativeWeight,
                Action = action,
                DisplayData = new FWPM_DISPLAY_DATA0(name, description),
                FilterKey = filterKey.Value,
                Flags = FWPM_FILTER_FLAGS.FWPM_FILTER_FLAG_PERSISTENT,
                NumFilterConditions = 0,
                // FilterCondition
            };

            WIN32_ERROR result = NativeMethods.FwpmFilterAdd0(this.engineHandle, filter, null, out ulong id);
            ValidateResult(result);
            
            return id;
        }

        void AddNamedPipeFilter(
            Guid interfaceUUID,
            int protocol,
            int operationNumber,
            int weight,
            string namedPipe,

            int action
            )
        {

        }

        public void RemoveFilter(ulong id)
        {
            WIN32_ERROR result = NativeMethods.FwpmFilterDeleteById0(this.engineHandle, id);
            ValidateResult(result);
        }

        public void Dispose()
        {
            this.engineHandle?.Dispose();
        }

        private static void ValidateResult(WIN32_ERROR code)
        {
            if(code == WIN32_ERROR.ERROR_SUCCESS)
            {
                return;
            }

            var genericException = new Win32Exception((int)code);
            Exception exceptionToThrow;

            switch (code)
            {
                case WIN32_ERROR.ERROR_INVALID_PARAMETER:
                    exceptionToThrow = new ArgumentException(genericException.Message, genericException);
                    break;
                case WIN32_ERROR.ERROR_ACCESS_DENIED:
                    exceptionToThrow = new UnauthorizedAccessException(genericException.Message, genericException);
                    break;
                case WIN32_ERROR.ERROR_NOT_ENOUGH_MEMORY:
                case WIN32_ERROR.ERROR_OUTOFMEMORY:
                    exceptionToThrow = new OutOfMemoryException(genericException.Message, genericException);
                    break;
                default:
                    // TODO: Handle RPC_STATUS.RPC_S_SERVER_UNAVAILABLE.
                    // We were not able to translate the Win32Exception to a more specific type.
                    exceptionToThrow = genericException;
                    break;
            }

            throw exceptionToThrow;
        }
    }
}
