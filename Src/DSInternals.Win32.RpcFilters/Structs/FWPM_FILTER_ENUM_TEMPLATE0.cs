using System.Runtime.InteropServices;
using Windows.Win32.NetworkManagement.WindowsFilteringPlatform;

namespace DSInternals.Win32.RpcFilters;

/// <summary>
/// Filter enumeration template.
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal sealed class FWPM_FILTER_ENUM_TEMPLATE0
{
    private byte[]? providerKey;

    /// <summary>
    /// Uniquely identifies the provider associated with this filter.
    /// </summary>
    public Guid? ProviderKey
    {
        get
        {
            if (providerKey != null)
            {
                return new Guid(providerKey);
            }
            else
            {
                return null;
            }
        }
        set
        {
            if (value.HasValue)
            {
                this.providerKey = value.Value.ToByteArray();
            }
            else
            {
                this.providerKey = null;
            }
        }
    }

    /// <summary>
    /// Layer whose fields are to be enumerated.
    /// </summary>
    public Guid LayerKey;

    /// <summary>
    /// Value that determines how the filter conditions are interpreted.
    /// </summary>
    public FWP_FILTER_ENUM_TYPE EnumType;

    /// <summary>
    /// Flags that modify the behavior of the enumeration.
    /// </summary>
    public FWP_FILTER_ENUM_FLAGS Flags;

    /// <summary>
    /// Used to limit the number of filters enumerated.
    /// </summary>
    private IntPtr ProviderContextTemplate;

    /// <summary>
    /// Number of filter conditions.
    /// </summary>
    private int NumFilterConditions;

    /// <summary>
    /// Distinct filter conditions.
    /// </summary>
    private IntPtr FilterCondition;

    /// <summary>
    /// Only filters whose action type contains at least one of the bits in actionMask will be returned. 
    /// </summary>
    public FWP_ACTION_TYPE ActionMask;

    /// <summary>
    /// Uniquely identifies the callout.
    /// </summary>
    private byte[]? calloutKey;

    /// <summary>
    /// Uniquely identifies the callout.
    /// </summary>
    public Guid? CalloutKey
    {
        get
        {
            if (calloutKey != null)
            {
                return new Guid(calloutKey);
            }
            else
            {
                return null;
            }
        }
        set
        {
            if (value.HasValue)
            {
                this.calloutKey = value.Value.ToByteArray();
            }
            else
            {
                this.calloutKey = null;
            }
        }
    }
}
