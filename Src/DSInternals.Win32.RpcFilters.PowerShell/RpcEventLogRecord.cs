using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Security.Principal;

namespace DSInternals.Win32.RpcFilters.PowerShell;

public class RpcEventLogRecord
{
    /// <summary>
    /// Event ID 5712: A Remote Procedure Call (RPC) was attempted.
    /// </summary>
    private const int RpcEventId = 5712;

    public DateTime? TimeCreated { get; private set; }

    public bool Allowed { get; private set; }
    public string MachineName { get; private set; }

    public SecurityIdentifier UserSid { get; private set; }
    public string UserName { get; private set; }
    public string UserDomain { get; private set; }
    public ulong UserLogonId { get; private set; }

    public ushort? RemotePort { get; private set; }

    public IPAddress? RemoteIPAddress { get; private set; }
    public Guid InterfaceUUID { get; private set; }
    public string? Protocol => WellKnownProtocolTranslator.ToProtocolName(this.InterfaceUUID);
    public ushort? OperationNumber { get; private set; }
    public string? Operation => WellKnownProtocolTranslator.ToOperationName(this.InterfaceUUID, this.OperationNumber);
    public RpcProtocolSequence Transport { get; private set; }
    public RpcAuthenticationType AuthenticationType { get; private set; }
    public RpcAuthenticationLevel AuthenticationLevel { get; private set; }
    public string ProcessName { get; private set; }
    public uint ProcessId { get; private set; }

    public RpcEventLogRecord(EventLogRecord record)
    {
        if (record == null)
        {
            throw new ArgumentNullException(nameof(record));
        }

        if (record.Id != RpcEventId)
        {
            throw new ArgumentException($"Event ID {RpcEventId} expected.", nameof(record));
        }

        // Process system properties
        this.TimeCreated = record.TimeCreated;
        this.MachineName = record.MachineName;
        this.Allowed = ((StandardEventKeywords)(record.Keywords ?? default)).HasFlag(StandardEventKeywords.AuditSuccess);

        // Process event data
        this.UserSid = (SecurityIdentifier)record.Properties[0].Value;
        this.UserName = (string)record.Properties[1].Value;
        this.UserDomain = (string)record.Properties[2].Value;
        this.UserLogonId = (ulong)record.Properties[3].Value;
        this.ProcessId = (uint)record.Properties[4].Value;
        this.ProcessName = (string)record.Properties[5].Value;
        this.InterfaceUUID = (Guid)record.Properties[8].Value;
        this.AuthenticationType = (RpcAuthenticationType)record.Properties[10].Value;
        this.AuthenticationLevel = (RpcAuthenticationLevel)record.Properties[11].Value;

        // Try parsing the transport protocol sequence value from string
        Enum.TryParse<RpcProtocolSequence>((string)record.Properties[9].Value, true, out RpcProtocolSequence protocolSequence);
        this.Transport = protocolSequence;

        // IP addresses and ports might not be unavailable for named pipe connections
        IPAddress.TryParse((string?)record.Properties[6].Value, out IPAddress? parsedAddress);
        this.RemoteIPAddress = IPAddress.Any.Equals(parsedAddress) ? null : parsedAddress;

        // Port number is stored as a string in the event data
        UInt16.TryParse((string?)record.Properties[7].Value, out var parsedPort);
        this.RemotePort = parsedPort == default ? null : parsedPort;

        if (record.Properties.Count >= 13)
        {
            // RPC operation number is only available since Windows 11 24H2 or Windows Server 2025
            // Event data stores OpNums as UInt32, but the actual data range should not exceed UInt16
            this.OperationNumber = (ushort?)((uint?)record.Properties[12].Value);
        }
    }
}
