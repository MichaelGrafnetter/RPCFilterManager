# RPC Filters Interop Assembly Project

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](../LICENSE)
[![.NET Framework 4.8+](https://img.shields.io/badge/.NET%20Framework-4.8%2B-007FFF.svg)](#)
[![.NET 8+](https://img.shields.io/badge/.NET-8%2B-007FFF.svg)](#)
[![Continuous Integration Status](https://github.com/MichaelGrafnetter/RPCFilterManager/actions/workflows/autobuild.yml/badge.svg)](https://github.com/RPCFilterManager/webauthn-interop/actions)

**A .NET Library and PowerShell Module for managing Windows RPC Filters**

## Interop Assembly

The `DSInternals.Win32.RpcFilters` library allows .NET applications to directly interact with Windows RPC Fiters.

## PowerShell Module

The [DSInternals.RpcFilters](https://www.powershellgallery.com/packages/DSInternals.RpcFilters) PowerShell module
exposes the functionality of the `DSInternals.Win32.RpcFilters` through PowerShell cmdlets.

## Examples

### PowerShell

```powershell
Import-Module -Name DSInternals.RpcFilters

Get-RpcFilter

New-RpcFilter

Get-RpcFilter | where Name -eq 'Test' | Remove-RpcFilter
```

### C#

The following example shows how RPC filters can be managed by the .NET interop library.
Note that the code is only meant to showcase all the possible parameters,
so the resulting filter is not meaningful at all.

```cs
using DSInternals.Win32.RpcFilters;
using System.Net;

// Open a Windows Filtering Platform (WFP) session
using (var fw = new RpcFilterManager())
{
    // Fetch the effective list of RPC filters
    var filters = fw.GetFilters();

    // Register a new RPC filter
    var filter = new RpcFilter()
    {
        Name = "TestFilter",
        Description = "Test filter description",
        Action = RpcFilterAction.Permit,
        InterfaceUUID = WellKnownProtocols.Registry.ToInterfaceUUID(),
        OperationNumber = 25,
        Transport = RpcProtocolSequence.ncacn_ip_tcp,
        NamedPipe = "winreg",
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
}
```

## Known Limitations

### Operation Numbers

The FWPM_CONDITION_RPC_OPNUM filter condition has been backported to downlevel Windows versions. (WS2019)

### Subnets

### Named Pipes

## Acknowledgements

- [Zero Networks: Stopping Lateral Movement via the RPC Firewall](https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall)
- [Akamai: A Definitive Guide to the Remote Procedure Call (RPC) Filter](https://www.akamai.com/blog/security/guide-rpc-filter)
