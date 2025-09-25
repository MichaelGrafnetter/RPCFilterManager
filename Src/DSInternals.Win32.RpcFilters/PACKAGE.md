## About

Library for managing Windows RPC Filters.

## Main Types

The main types provided by this library are:

- `RpcFilterManager` - Main class for interacting with the Windows Filtering Platform (WFP) to manage RPC filters.
- `RpcFilter` - Represents a single RPC filter with all its properties and conditions.
- `WellKnownProtocolTranslator` - Translates well-known protocol names to their corresponding UUIDs.

## How to Use

The following example shows how RPC filters can be managed using this library.
Note that the code is only meant to showcase all the possible parameters,
so the resulting filter is not meaningful at all.

```cs
using DSInternals.Win32.RpcFilters;
using System.Net;

// Open a Windows Filtering Platform (WFP) session
using var fw = new RpcFilterManager();

// Fetch the effective list of RPC filters
var filters = fw.GetFilters();

// Register a new RPC filter
var filter = new RpcFilter()
{
    Name = "TestFilter",
    Description = "Test filter description",
    Action = RpcFilterAction.Permit,
    InterfaceUUID = WellKnownProtocols.RemoteRegistry.ToInterfaceUUID(),
    OperationNumber = 25,
    Transport = RpcProtocolSequence.ncacn_ip_tcp,
    NamedPipe = "\\PIPE\\winreg",
    LocalPort = 56345,
    DcomAppId = Guid.Parse("10000000-0000-0000-0000-000000000002"),
    SDDL = "D:(A;;CC;;;BA)",
    Audit = true,
    IsPersistent = true,
    AuthenticationLevel = RpcAuthenticationLevel.PacketPrivacy,
    AuthenticationType = RpcAuthenticationType.Kerberos,
    IsBootTimeEnforced = false,
    ImageName = "svchost.exe",
    RemoteAddress = IPAddress.Parse("fe80::bf1c:8c8e:f09d:c074"),
    LocalAddress = IPAddress.Parse("10.255.255.0"),
    LocalAddressMask = 24,
    Weight = 3
};

ulong id = fw.AddFilter(filter);

// Delete the freshly registered RPC filter
fw.RemoveFilter(id);
```

## License

`DSInternals.Win32.RpcFilters` is released as open source under the [MIT license](https://licenses.nuget.org/MIT).
