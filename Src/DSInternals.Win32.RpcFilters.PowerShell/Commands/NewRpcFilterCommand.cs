using System.Management.Automation;
using System.Net;
using System.Security.AccessControl;

namespace DSInternals.Win32.RpcFilters.PowerShell.Commands;

[Cmdlet(VerbsCommon.New, "RpcFilter", DefaultParameterSetName = CustomProtocolParameterSet)]
[OutputType(typeof(RpcFilter))]
public class NewRpcFilterCommand : RpcFilterCommandBase
{
    private const string CustomProtocolParameterSet = "CustomProtocol";
    private const string WellKnownProtocolParameterSet = "WellKnownProtocol";
    private const string WellKnownOperationParameterSet = "WellKnownOperation";

    [Parameter()]
    public SwitchParameter PassThrough { get; set; } = default;

    [Parameter()]
    [Alias("Boot")]
    public SwitchParameter BootTimeEnforced { get; set; } = default;

    [Parameter()]
    public SwitchParameter Persistent { get; set; } = default;

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    public string? Name { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    public string? Description { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    public string? ImageName { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    public string? NamedPipe { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    public Guid? FilterKey { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    public Guid? DcomAppId { get; set; }

    [Parameter(Mandatory = false, ParameterSetName = CustomProtocolParameterSet, ValueFromPipelineByPropertyName = true)]
    [Alias("RpcProtocol", "Protocol", "ProtocolUUID")]
    public Guid? InterfaceUUID { get; set; }

    [Parameter(Mandatory = true, ParameterSetName = WellKnownProtocolParameterSet, ValueFromPipelineByPropertyName = true)]
    [Alias("WellKnownInterface")]
    public WellKnownProtocol? WellKnownProtocol { get; set; }

    [Parameter(Mandatory = true, ParameterSetName = WellKnownOperationParameterSet, ValueFromPipelineByPropertyName = true)]
    public WellKnownOperation? WellKnownOperation { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    public Guid? ProviderKey { get; set; }

    [Parameter(Mandatory = true, ValueFromPipelineByPropertyName = true)]
    public RpcFilterAction Action { get; set; }

    [Parameter(ValueFromPipelineByPropertyName = true)]
    public SwitchParameter Audit { get; set; } = default;

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    public RpcAuthenticationLevel? AuthenticationLevel { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    public RpcAuthenticationType? AuthenticationType { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [Alias("ProtSeq", "Binding", "Transport")]
    public RpcProtocolSequence? ProtocolSequence { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [Alias("SDDL", "Permissions", "DACL")]
    public RawSecurityDescriptor? SecurityDescriptor { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    public IPAddress? RemoteAddress { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateRange(1, 128)]
    public byte? RemoteAddressMask { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    public IPAddress? LocalAddress { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateRange(1, 128)]
    public byte? LocalAddressMask { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateRange(1, ushort.MaxValue)]
    public ushort? LocalPort { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    public ulong? Weight { get; set; }

    [Parameter(Mandatory = false, ParameterSetName = CustomProtocolParameterSet, ValueFromPipelineByPropertyName = true)]
    [Parameter(Mandatory = false, ParameterSetName = WellKnownProtocolParameterSet, ValueFromPipelineByPropertyName = true)]
    [Alias("OpNum")]
    public ushort? OperationNumber { get; set; }

    protected override void ProcessRecord()
    {
        base.ProcessRecord();

        try
        {
            // Translate the well-known protocol and operation names first.
            if (WellKnownProtocol.HasValue)
            {
                InterfaceUUID = WellKnownProtocol.Value.Translate();
            }

            if (WellKnownOperation.HasValue)
            {
                (InterfaceUUID, OperationNumber) = WellKnownOperation.Value.Translate();
            }

            // Create and save the filter.
            var filter = new RpcFilter()
            {
                Name = Name ?? RpcFilter.DefaultName,
                Description = Description ?? RpcFilter.DefaultDescription,
                FilterKey = FilterKey ?? Guid.NewGuid(),
                Action = Action,
                Audit = Audit.IsPresent,
                AuthenticationLevel = AuthenticationLevel,
                AuthenticationType = AuthenticationType,
                DcomAppId = DcomAppId,
                ImageName = ImageName,
                InterfaceUUID = InterfaceUUID,
                IsBootTimeEnforced = BootTimeEnforced.IsPresent,
                IsPersistent = Persistent.IsPresent,
                LocalAddress = LocalAddress,
                LocalAddressMask = LocalAddressMask,
                LocalPort = LocalPort,
                Protocol = ProtocolSequence,
                RemoteAddress = RemoteAddress,
                RemoteAddressMask = RemoteAddressMask,
                SecurityDescriptor = SecurityDescriptor,
                Weight = Weight,
                OperationNumber = OperationNumber,
                NamedPipe = NamedPipe,
                ProviderKey = ProviderKey
            };

            // TODO: Verbose message

#pragma warning disable CS8602 // Dereference of a possibly null reference.
            ulong filterId = RpcFilterManager.AddFilter(filter);
#pragma warning restore CS8602 // Dereference of a possibly null reference.

            if (PassThrough.IsPresent)
            {
                WriteObject(filter);
            }
        }
        catch (Exception ex)
        {
            // TODO: Improve this error report
            WriteError(new ErrorRecord(ex, "RpcFilterCreationFailed", ErrorCategory.InvalidOperation, null));
        }
    }
}
