using System.Management.Automation;

namespace DSInternals.Win32.RpcFilters.PowerShell.Commands;

[Cmdlet(VerbsCommon.Get, "RpcFilter", DefaultParameterSetName = ParameterSetByProviderKey)]
[OutputType(typeof(RpcFilter))]
public class GetRpcFilterCommand : RpcFilterCommandBase
{
    private const string ParameterSetByProviderKey = "Default";
    private const string ParameterSetZeroNetworks = "ZeroNetworks";

    /// <summary>
    /// The WFP provider key used by the Zero Networks RPC Firewall.
    /// </summary>
    private static readonly Guid ZeroNetworksRpcFirewallProviderKey = new(0x17171717, 0x1717, 0x1717, [0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17]); // 17171717-1717-1717-1717-171717171717

    [Parameter(Mandatory = false, Position = 0, ParameterSetName = ParameterSetByProviderKey)]
    [ValidateNotNull()]
    [Alias("Provider", "ProviderId", "RpcFilterProvider", "RpcFilterProviderId")]
    public Guid? ProviderKey { get; set; }

    [Parameter(Mandatory = true, Position = 0, ParameterSetName = ParameterSetZeroNetworks)]
    [Alias("RpcFirewall")]
    public SwitchParameter ZeroNetworks { get; set; }

    protected override void ProcessRecord()
    {
        base.ProcessRecord();

        if (ZeroNetworks.IsPresent)
        {
            ProviderKey = ZeroNetworksRpcFirewallProviderKey;
        }

        try
        {
#pragma warning disable CS8602 // Dereference of a possibly null reference.
            var filterEnumerator = RpcFilterManager.GetFilters(ProviderKey);
#pragma warning restore CS8602 // Dereference of a possibly null reference.

            foreach (var filter in filterEnumerator)
            {
                WriteObject(filter);
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            ThrowTerminatingError(new ErrorRecord(ex, "RpcFilterAccessDenied", ErrorCategory.PermissionDenied, null));
        }
        catch (Exception ex)
        {
            ThrowTerminatingError(new ErrorRecord(ex, "RpcFilterRetrievalFailed", ErrorCategory.ReadError, null));
        }
    }
}
