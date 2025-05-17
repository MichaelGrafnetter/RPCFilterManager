using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Security.Principal;

namespace DSInternals.Win32.RpcFilters.PowerShell;

/// <summary>
/// Represents a single event log record for an RPC filter event with ID 5712.
/// </summary>
public class RpcEventLogRecord
{
    /// <summary>
    /// Event ID 5712: A Remote Procedure Call (RPC) was attempted.
    /// </summary>
    private const int RpcEventId = 5712;

    /// <summary>
    /// Gets the time that the event was created.
    /// </summary>
    public DateTime? TimeCreated { get; private set; }

    public bool Allowed { get; private set; }

    /// <summary>
    /// Gets the name of the computer on which this event was logged.
    /// </summary>
    public string MachineName { get; private set; }

    /// <summary>
    /// Gets the security identifier (SID) of the user who attempted the RPC call.
    /// </summary>
    public SecurityIdentifier UserSid { get; private set; }

    /// <summary>
    /// Gets the name of the user who attempted the RPC call.
    /// </summary>
    public string UserName { get; private set; }

    /// <summary>
    /// Gets the domain of the user who attempted the RPC call.
    /// </summary>
    public string UserDomain { get; private set; }

    /// <summary>
    /// Gets the logon ID of the user who attempted the RPC call.
    /// </summary>
    public ulong UserLogonId { get; private set; }

    /// <summary>
    /// Gets the remote port number used for the RPC call.
    /// </summary>
    public ushort? RemotePort { get; private set; }

    /// <summary>
    /// Gets the remote IP address used for the RPC call.
    /// </summary>
    /// <remarks>IP addresses are only populated when a TCP/IP binding is used.</remarks>
    public IPAddress? RemoteIPAddress { get; private set; }

    /// <summary>
    /// Gets the UUID of the RPC interface used.
    /// </summary>
    public Guid InterfaceUUID { get; private set; }

    /// <summary>
    /// Gets the name of the RPC interface used for the RPC call, if available.
    /// </summary>
    public string? Protocol => WellKnownProtocolTranslator.ToProtocolName(this.InterfaceUUID);

    /// <summary>
    /// Gets the operation number of the RPC call.
    /// </summary>
    /// <remarks>OpNums are only populated since Windows 11 24H2 or Windows Server 2025</remarks>
    public ushort? OperationNumber { get; private set; }

    /// <summary>
    /// Gets the name of the RPC operation used for the RPC call, if available.
    /// </summary>
    public string? Operation => WellKnownProtocolTranslator.ToOperationName(this.InterfaceUUID, this.OperationNumber);

    /// <summary>
    /// Gets the transport protocol sequence used for the RPC call.
    /// </summary>
    public RpcProtocolSequence Transport { get; private set; }

    /// <summary>
    /// Gets the authentication type used for the RPC call.
    /// </summary>
    public RpcAuthenticationType AuthenticationType { get; private set; }

    /// <summary>
    /// Gets the authentication level used for the RPC call.
    /// </summary>
    public RpcAuthenticationLevel AuthenticationLevel { get; private set; }

    /// <summary>
    /// Gets the name of the RPC server process.
    /// </summary>
    public string ProcessName { get; private set; }

    /// <summary>
    /// Gets the ID of the RPC server process.
    /// </summary>
    public uint ProcessId { get; private set; }

    /// <summary>
    /// Creates a new instance of the <see cref="RpcEventLogRecord"/> class from a generic <see cref="EventLogRecord" /> instance.
    /// </summary>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
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
        bool ipParseSuccessful = IPAddress.TryParse((string?)record.Properties[6].Value, out IPAddress? parsedAddress);
        if (ipParseSuccessful && !IPAddress.Any.Equals(parsedAddress))
        {
            this.RemoteIPAddress = parsedAddress;
        }

        // Port number is stored as a string in the event data
        bool portParseSuccessful = UInt16.TryParse((string?)record.Properties[7].Value, out var parsedPort);
        if (portParseSuccessful && parsedPort != default)
        {
            this.RemotePort = parsedPort;
        }

        if (record.Properties.Count >= 13)
        {
            // RPC operation number is only available since Windows 11 24H2 or Windows Server 2025
            // Event data stores OpNums as UInt32, but the actual data range should not exceed UInt16
            this.OperationNumber = (ushort?)((uint?)record.Properties[12].Value);
        }
    }
}
