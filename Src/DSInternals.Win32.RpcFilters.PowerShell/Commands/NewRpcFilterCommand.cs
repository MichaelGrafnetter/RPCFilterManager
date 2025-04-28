using System.Management.Automation;
using System.Net;
using System.Net.Sockets;
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

    // The comparison is case-sensitive, as the underlaying filter is case sensitive.
    // Sample value: \PIPE\winreg
    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidatePattern("^\\\\PIPE\\\\.+")]
    [Alias("Pipe", "PipeName")]
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
    [Alias("ProtSeq", "Binding", "ProtocolSequence")]
    public RpcProtocolSequence? Transport { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [Alias("SDDL", "Permissions", "DACL")]
    public RawSecurityDescriptor? SecurityDescriptor { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [Alias("IPAddress", "Address")]
    public IPAddress? RemoteAddress { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateRange(1, 128)]
    [Alias("Mask", "PrefixLength", "Prefix", "RemoteAddressPrefix", "RemoteAddressPrefixLength")]
    public byte? RemoteAddressMask { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    public IPAddress? LocalAddress { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateRange(1, 128)]
    public byte? LocalAddressMask { get; set; }

    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateRange(1, ushort.MaxValue)]
    public ushort? LocalPort { get; set; }

    // The .NET wrapper currently only supports weight ranges (0-15) instead of supporting the full UINT64 range as well.
    [Parameter(Mandatory = false, ValueFromPipelineByPropertyName = true)]
    [ValidateRange(0, 15)]
    [Alias("WeightRange")]
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
            if (WellKnownOperation.HasValue)
            {
                (WellKnownProtocol, OperationNumber) = WellKnownOperation.Value.ToOperationNumber();
            }

            if (WellKnownProtocol.HasValue)
            {
                InterfaceUUID = WellKnownProtocol.Value.ToInterfaceUUID();
            }

            // Perform parameter validation.
            bool namedPipesUsed = NamedPipe != null || Transport == RpcProtocolSequence.ncacn_np;
            bool ipAddressUsed = RemoteAddress != null || LocalAddress != null;

            if (namedPipesUsed && ipAddressUsed)
            {
                WriteWarning("Filters with both IP address and named pipe conditions are ignored by Windows.");
            }

            if (WellKnownProtocol.SupportsNamedPipes() && ipAddressUsed)
            {
                WriteWarning("The target interface supports a named pipe binding. Only TCP/IP bindings work with IP address conditions.");
            }

            if (OperationNumber.HasValue && !RpcFilterManager.IsOpnumFilterSupported)
            {
                WriteWarning("Filters with OpNum conditions only work on Windows 11 24H2 and Windows Server 2025 or newer systems.");
            }

            if (RemoteAddressMask.HasValue && RemoteAddress == null)
            {
                WriteError(new ErrorRecord(new ArgumentException("RemoteAddressMask requires RemoteAddress to be set."), "RemoteMaskRequiresRemoteAddress", ErrorCategory.InvalidArgument, null));
                return;
            }

            if (LocalAddressMask.HasValue && LocalAddress == null)
            {
                WriteError(new ErrorRecord(new ArgumentException("LocalAddressMask requires LocalAddress to be set."), "LocalMaskRequiresLocalAddress", ErrorCategory.InvalidArgument, null));
                return;
            }

            if (ipAddressUsed)
            {
                bool isRemoteIPv4Subnet =
                    RemoteAddress?.AddressFamily == AddressFamily.InterNetwork &&
                    RemoteAddressMask.HasValue && RemoteAddressMask < 32;

                bool isRemoteIPv6Subnet =
                    RemoteAddress?.AddressFamily == AddressFamily.InterNetworkV6 &&
                    RemoteAddressMask.HasValue && RemoteAddressMask < 128;

                bool isLocalIPv4Subnet =
                    LocalAddress?.AddressFamily == AddressFamily.InterNetwork &&
                    LocalAddressMask.HasValue && LocalAddressMask < 32;

                bool isLocalIPv6Subnet =
                    LocalAddress?.AddressFamily == AddressFamily.InterNetworkV6 &&
                    LocalAddressMask.HasValue && LocalAddressMask < 128;

                bool isRemoteSubnet = isRemoteIPv4Subnet || isRemoteIPv6Subnet;
                bool isLocalSubnet = isLocalIPv4Subnet || isLocalIPv6Subnet;

                if (isRemoteSubnet || isLocalSubnet)
                {
                    WriteWarning("Filters with IP address subnet conditions are ignored by Windows.");
                }
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
                Transport = Transport,
                RemoteAddress = RemoteAddress,
                RemoteAddressMask = RemoteAddressMask,
                SecurityDescriptor = SecurityDescriptor,
                Weight = Weight,
                OperationNumber = OperationNumber,
                NamedPipe = NamedPipe,
                ProviderKey = ProviderKey
            };

            WriteVerbose($"Creating filter {filter.Name} with key {filter.FilterKey}.");

#pragma warning disable CS8602 // Dereference of a possibly null reference.
            ulong filterId = RpcFilterManager.AddFilter(filter);
#pragma warning restore CS8602 // Dereference of a possibly null reference.

            if (PassThrough.IsPresent)
            {
                WriteObject(filter);
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            WriteError(new ErrorRecord(ex, "RpcFilterAccessDenied", ErrorCategory.PermissionDenied, null));
        }
        catch (ArgumentException ex)
        {
            WriteError(new ErrorRecord(ex, "RpcFilterInvalidArgument", ErrorCategory.InvalidArgument, null));
        }
        catch (Exception ex)
        {
            WriteError(new ErrorRecord(ex, "RpcFilterCreationFailed", ErrorCategory.WriteError, null));
        }
    }
}
