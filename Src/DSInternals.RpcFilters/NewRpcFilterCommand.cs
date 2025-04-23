using System.Management.Automation;
using System.Net;

namespace DSInternals.Win32.RpcFilters.PowerShell;

[Cmdlet(VerbsCommon.New, "RpcFilter")]
[OutputType(typeof(RpcFilter))]
public class NewRpcFilterCommand : RpcFilterCommandBase
{
    [Parameter()]
    public SwitchParameter PassThrough { get; set; } = default;

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty()]
    public string? Name { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty()]
    public string? Description { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNull()]
    public Guid? FilterKey { get; set; }

    [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true)]
    public RpcFilterAction Action { get; set; }

    [Parameter(ValueFromPipelineByPropertyName = true)]
    public SwitchParameter Audit { get; set; } = default;

    [Parameter(ValueFromPipelineByPropertyName = true)]
    [ValidateNotNull()]
    public RpcAuthenticationLevel? AuthenticationLevel { get; set; }

    [Parameter(ValueFromPipelineByPropertyName = true)]
    [ValidateNotNull()]
    public RpcAuthenticationType? AuthenticationType { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNullOrEmpty()]
    public string? SecurityDescriptor { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNull()]
    public IPAddress? RemoteAddress { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNull()]
    [ValidateRange(1, 128)]
    public byte? RemoteAddressMask { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNull()]
    public IPAddress? LocalAddress { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateNotNull()]
    [ValidateRange(1, 128)]
    public byte? LocalAddressMask { get; set; }

    protected override void ProcessRecord()
    {
        base.ProcessRecord();

        try
        {
            var filter = new RpcFilter()
            {
                Name = this.Name ?? RpcFilter.DefaultName,
                Description = this.Description ?? RpcFilter.DefaultDescription,
                FilterKey = this.FilterKey ?? Guid.NewGuid(),
                Action = this.Action,
                Audit = this.Audit.IsPresent,
                AuthenticationLevel = this.AuthenticationLevel,
                AuthenticationType = this.AuthenticationType,
                // DcomAppId
                // ImageName
                // InterfaceUUID
                // IsBootTimeEnforced
                // IsPersistent
                LocalAddress = this.LocalAddress,
                LocalAddressMask = this.LocalAddressMask,
                // LocalPort
                // Protocol
                RemoteAddress = this.RemoteAddress,
                RemoteAddressMask = this.RemoteAddressMask,
                SDDL = this.SecurityDescriptor,
                // Weight
            };

#pragma warning disable CS8602 // Dereference of a possibly null reference.
            ulong filterId = this.RpcFilterManager.AddFilter(filter);
#pragma warning restore CS8602 // Dereference of a possibly null reference.

            if (this.PassThrough.IsPresent)
            {
                this.WriteObject(filter);
            }
        }
        catch (Exception ex)
        {
            // TODO: Improve this error report
            this.WriteError(new ErrorRecord(ex, "RpcFilterCreationFailed", ErrorCategory.InvalidOperation, null));
        }
    }
}
