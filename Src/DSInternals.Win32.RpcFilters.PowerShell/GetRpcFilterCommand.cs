using System.Management.Automation;

namespace DSInternals.Win32.RpcFilters.PowerShell;

[Cmdlet(VerbsCommon.Get, "RpcFilter", DefaultParameterSetName = ParameterSetByProviderKey)]
[OutputType(typeof(RpcFilter))]
public class GetRpcFilterCommand : RpcFilterCommandBase
{
    private const string ParameterSetByProviderKey = "Default";
    private const string ParameterSetZeroNetworks = "ZeroNetworks";
    private static readonly Guid ZeroNetworksRpcFirewallProviderKey = new(0x17171717, 0x1717, 0x1717, [0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17]); 

    [Parameter(Mandatory = false, Position = 0, ParameterSetName = ParameterSetByProviderKey)]
    [Alias("Provider", "ProviderId", "RpcFilterProvider", "RpcFilterProviderId")]
    public Guid? ProviderKey { get; set; }

    [Parameter(Mandatory = true, Position = 0, ParameterSetName = ParameterSetZeroNetworks)]
    [Alias("RpcFirewall")]
    public SwitchParameter ZeroNetworks { get; set; }

    protected override void ProcessRecord()
    {
        base.ProcessRecord();

        if (this.ZeroNetworks.IsPresent)
        {
            this.ProviderKey = ZeroNetworksRpcFirewallProviderKey;
        }

        // TODO: Exception handling

#pragma warning disable CS8602 // Dereference of a possibly null reference.
        var filterEnumerator = this.RpcFilterManager.GetFilters(this.ProviderKey);
#pragma warning restore CS8602 // Dereference of a possibly null reference.

        foreach (var filter in filterEnumerator)
        {
            this.WriteObject(filter);
        }

    }
}
