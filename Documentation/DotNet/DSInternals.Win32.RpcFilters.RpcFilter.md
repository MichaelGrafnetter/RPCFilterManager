# <a id="DSInternals_Win32_RpcFilters_RpcFilter"></a> Class RpcFilter

Namespace: [DSInternals.Win32.RpcFilters](DSInternals.Win32.RpcFilters.md)  
Assembly: DSInternals.Win32.RpcFilters.dll  

Stores the state associated with a RPC filter.

```csharp
public sealed class RpcFilter
```

#### Inheritance

[object](https://learn.microsoft.com/dotnet/api/system.object) ← 
[RpcFilter](DSInternals.Win32.RpcFilters.RpcFilter.md)

#### Inherited Members

[object.ToString\(\)](https://learn.microsoft.com/dotnet/api/system.object.tostring), 
[object.Equals\(object\)](https://learn.microsoft.com/dotnet/api/system.object.equals\#system\-object\-equals\(system\-object\)), 
[object.Equals\(object, object\)](https://learn.microsoft.com/dotnet/api/system.object.equals\#system\-object\-equals\(system\-object\-system\-object\)), 
[object.ReferenceEquals\(object, object\)](https://learn.microsoft.com/dotnet/api/system.object.referenceequals), 
[object.GetHashCode\(\)](https://learn.microsoft.com/dotnet/api/system.object.gethashcode), 
[object.GetType\(\)](https://learn.microsoft.com/dotnet/api/system.object.gettype)

## Constructors

### <a id="DSInternals_Win32_RpcFilters_RpcFilter__ctor"></a> RpcFilter\(\)

Constructs a new instance of the <xref href="DSInternals.Win32.RpcFilters.RpcFilter" data-throw-if-not-resolved="false"></xref> class with default values.

```csharp
public RpcFilter()
```

## Fields

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_DefaultDescription"></a> DefaultDescription

Default description of a newly created filter.

```csharp
public const string DefaultDescription = "RPC Filter"
```

#### Field Value

 [string](https://learn.microsoft.com/dotnet/api/system.string)

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_DefaultName"></a> DefaultName

Default name of a newly created filter.

```csharp
public const string DefaultName = "RPCFilter"
```

#### Field Value

 [string](https://learn.microsoft.com/dotnet/api/system.string)

## Properties

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_Action"></a> Action

Specifies the action to be performed if all the filter conditions are true.

```csharp
public RpcFilterAction Action { get; set; }
```

#### Property Value

 [RpcFilterAction](DSInternals.Win32.RpcFilters.RpcFilterAction.md)

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_Audit"></a> Audit

Indicates whether incoming RPC calls and their parameters are audited as part of C2 and common criteria compliance.

```csharp
public RpcFilterAuditOptions Audit { get; set; }
```

#### Property Value

 [RpcFilterAuditOptions](DSInternals.Win32.RpcFilters.RpcFilterAuditOptions.md)

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_AuthenticationLevel"></a> AuthenticationLevel

The authentication level controls how much security a client or server wants from its SSP.

```csharp
public RpcAuthenticationLevel? AuthenticationLevel { get; set; }
```

#### Property Value

 [RpcAuthenticationLevel](DSInternals.Win32.RpcFilters.RpcAuthenticationLevel.md)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_AuthenticationLevelMatchType"></a> AuthenticationLevelMatchType

The match type (operator) for the authentication level.

```csharp
public NumericMatchType AuthenticationLevelMatchType { get; set; }
```

#### Property Value

 [NumericMatchType](DSInternals.Win32.RpcFilters.NumericMatchType.md)

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_AuthenticationLevelOperator"></a> AuthenticationLevelOperator

The authentication level operator as a string.

```csharp
public string AuthenticationLevelOperator { get; }
```

#### Property Value

 [string](https://learn.microsoft.com/dotnet/api/system.string)

#### Remarks

This read-only property is for display purposes only.

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_AuthenticationType"></a> AuthenticationType

Authentication service used for RPC connections.

```csharp
public RpcAuthenticationType? AuthenticationType { get; set; }
```

#### Property Value

 [RpcAuthenticationType](DSInternals.Win32.RpcFilters.RpcAuthenticationType.md)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_DcomAppId"></a> DcomAppId

The identification of the COM application.

```csharp
public Guid? DcomAppId { get; set; }
```

#### Property Value

 [Guid](https://learn.microsoft.com/dotnet/api/system.guid)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_Description"></a> Description

Optional filter description.

```csharp
public string? Description { get; set; }
```

#### Property Value

 [string](https://learn.microsoft.com/dotnet/api/system.string)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_EffectiveWeight"></a> EffectiveWeight

Contains the weight assigned to the filter.

```csharp
public ulong? EffectiveWeight { get; }
```

#### Property Value

 [ulong](https://learn.microsoft.com/dotnet/api/system.uint64)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_FilterId"></a> FilterId

Locally unique identifier of the filter.

```csharp
public ulong? FilterId { get; }
```

#### Property Value

 [ulong](https://learn.microsoft.com/dotnet/api/system.uint64)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_FilterKey"></a> FilterKey

Unique identifier of the filter.

```csharp
public Guid FilterKey { get; set; }
```

#### Property Value

 [Guid](https://learn.microsoft.com/dotnet/api/system.guid)

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_ImageName"></a> ImageName

The name of the application.

```csharp
public string? ImageName { get; set; }
```

#### Property Value

 [string](https://learn.microsoft.com/dotnet/api/system.string)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_InterfaceFlag"></a> InterfaceFlag

Reserved for internal use.

```csharp
public uint? InterfaceFlag { get; set; }
```

#### Property Value

 [uint](https://learn.microsoft.com/dotnet/api/system.uint32)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_InterfaceName"></a> InterfaceName

The name of the RPC interface.

```csharp
public string? InterfaceName { get; }
```

#### Property Value

 [string](https://learn.microsoft.com/dotnet/api/system.string)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_InterfaceUUID"></a> InterfaceUUID

The UUID of the RPC interface.

```csharp
public Guid? InterfaceUUID { get; set; }
```

#### Property Value

 [Guid](https://learn.microsoft.com/dotnet/api/system.guid)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_InterfaceVersion"></a> InterfaceVersion

The version of the RPC interface.

```csharp
public ushort? InterfaceVersion { get; set; }
```

#### Property Value

 [ushort](https://learn.microsoft.com/dotnet/api/system.uint16)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_IsBootTimeEnforced"></a> IsBootTimeEnforced

Indicates whether the filter is enforced at boot-time, even before BFE starts.

```csharp
public bool IsBootTimeEnforced { get; set; }
```

#### Property Value

 [bool](https://learn.microsoft.com/dotnet/api/system.boolean)

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_IsDisabled"></a> IsDisabled

Indicates whether the filter is disabled.

```csharp
public bool IsDisabled { get; }
```

#### Property Value

 [bool](https://learn.microsoft.com/dotnet/api/system.boolean)

#### Remarks

A provider's filters are disabled when the BFE starts if the provider has no associated Windows service name, or if the associated service is not set to auto-start.
This flag cannot be set when adding new filters. It can only be returned by BFE when getting or enumerating filters.

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_IsPersistent"></a> IsPersistent

Indicates whether the filter is persistent, that is, it survives across BFE stop/start.

```csharp
public bool IsPersistent { get; set; }
```

#### Property Value

 [bool](https://learn.microsoft.com/dotnet/api/system.boolean)

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_LocalAddress"></a> LocalAddress

The local IP address.

```csharp
public IPAddress? LocalAddress { get; set; }
```

#### Property Value

 [IPAddress](https://learn.microsoft.com/dotnet/api/system.net.ipaddress)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_LocalAddressMask"></a> LocalAddressMask

The local IP address mask.

```csharp
public byte? LocalAddressMask { get; set; }
```

#### Property Value

 [byte](https://learn.microsoft.com/dotnet/api/system.byte)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_LocalNetwork"></a> LocalNetwork

The local IP address and mask.

```csharp
public string? LocalNetwork { get; }
```

#### Property Value

 [string](https://learn.microsoft.com/dotnet/api/system.string)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_LocalPort"></a> LocalPort

The local transport protocol port number.

```csharp
public ushort? LocalPort { get; set; }
```

#### Property Value

 [ushort](https://learn.microsoft.com/dotnet/api/system.uint16)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_Name"></a> Name

Human-readable RPC filter name.

```csharp
public string Name { get; set; }
```

#### Property Value

 [string](https://learn.microsoft.com/dotnet/api/system.string)

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_NamedPipe"></a> NamedPipe

The name of the remote named pipe.

```csharp
public string? NamedPipe { get; set; }
```

#### Property Value

 [string](https://learn.microsoft.com/dotnet/api/system.string)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_OperationName"></a> OperationName

The name of the RPC operation.

```csharp
public string? OperationName { get; }
```

#### Property Value

 [string](https://learn.microsoft.com/dotnet/api/system.string)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_OperationNumber"></a> OperationNumber

The RPC OpNum for an RPC call made to an RPC listener.

```csharp
public ushort? OperationNumber { get; set; }
```

#### Property Value

 [ushort](https://learn.microsoft.com/dotnet/api/system.uint16)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_ProviderKey"></a> ProviderKey

Optional identifier of the policy provider that manages this filter.

```csharp
public Guid? ProviderKey { get; }
```

#### Property Value

 [Guid](https://learn.microsoft.com/dotnet/api/system.guid)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_RemoteAddress"></a> RemoteAddress

The remote IP address.

```csharp
public IPAddress? RemoteAddress { get; set; }
```

#### Property Value

 [IPAddress](https://learn.microsoft.com/dotnet/api/system.net.ipaddress)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_RemoteAddressMask"></a> RemoteAddressMask

The remote IP address mask.

```csharp
public byte? RemoteAddressMask { get; set; }
```

#### Property Value

 [byte](https://learn.microsoft.com/dotnet/api/system.byte)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_RemoteNetwork"></a> RemoteNetwork

The remote IP address and mask.

```csharp
public string? RemoteNetwork { get; }
```

#### Property Value

 [string](https://learn.microsoft.com/dotnet/api/system.string)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_SDDL"></a> SDDL

The identification of the remote user in SDDL format.

```csharp
public string? SDDL { get; set; }
```

#### Property Value

 [string](https://learn.microsoft.com/dotnet/api/system.string)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_SecurityDescriptor"></a> SecurityDescriptor

The identification of the remote user.

```csharp
public RawSecurityDescriptor? SecurityDescriptor { get; set; }
```

#### Property Value

 [RawSecurityDescriptor](https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.rawsecuritydescriptor)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_SecurityDescriptorNegativeMatch"></a> SecurityDescriptorNegativeMatch

Indicates whether the security descriptor should be negated.

```csharp
public bool SecurityDescriptorNegativeMatch { get; set; }
```

#### Property Value

 [bool](https://learn.microsoft.com/dotnet/api/system.boolean)

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_SecurityDescriptorOperator"></a> SecurityDescriptorOperator

The security descriptor operator as a string.

```csharp
public string SecurityDescriptorOperator { get; }
```

#### Property Value

 [string](https://learn.microsoft.com/dotnet/api/system.string)

#### Remarks

This read-only property is for display purposes only.

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_Transport"></a> Transport

Protocol family used by the RPC endpoint.

```csharp
public RpcProtocolSequence? Transport { get; set; }
```

#### Property Value

 [RpcProtocolSequence](DSInternals.Win32.RpcFilters.RpcProtocolSequence.md)?

### <a id="DSInternals_Win32_RpcFilters_RpcFilter_Weight"></a> Weight

The weight indicates the priority of the filter, where higher-numbered weights have higher priorities.

```csharp
public ulong? Weight { get; set; }
```

#### Property Value

 [ulong](https://learn.microsoft.com/dotnet/api/system.uint64)?

