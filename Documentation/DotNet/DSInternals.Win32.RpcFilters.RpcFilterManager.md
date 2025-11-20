# <a id="DSInternals_Win32_RpcFilters_RpcFilterManager"></a> Class RpcFilterManager

Namespace: [DSInternals.Win32.RpcFilters](DSInternals.Win32.RpcFilters.md)  
Assembly: DSInternals.Win32.RpcFilters.dll  

Manages RPC filters in the Windows Filtering Platform (WFP).

```csharp
public sealed class RpcFilterManager : IDisposable
```

#### Inheritance

[object](https://learn.microsoft.com/dotnet/api/system.object) ← 
[RpcFilterManager](DSInternals.Win32.RpcFilters.RpcFilterManager.md)

#### Implements

[IDisposable](https://learn.microsoft.com/dotnet/api/system.idisposable)

#### Inherited Members

[object.ToString\(\)](https://learn.microsoft.com/dotnet/api/system.object.tostring), 
[object.Equals\(object\)](https://learn.microsoft.com/dotnet/api/system.object.equals\#system\-object\-equals\(system\-object\)), 
[object.Equals\(object, object\)](https://learn.microsoft.com/dotnet/api/system.object.equals\#system\-object\-equals\(system\-object\-system\-object\)), 
[object.ReferenceEquals\(object, object\)](https://learn.microsoft.com/dotnet/api/system.object.referenceequals), 
[object.GetHashCode\(\)](https://learn.microsoft.com/dotnet/api/system.object.gethashcode), 
[object.GetType\(\)](https://learn.microsoft.com/dotnet/api/system.object.gettype)

## Constructors

### <a id="DSInternals_Win32_RpcFilters_RpcFilterManager__ctor"></a> RpcFilterManager\(\)

Opens a session to the filter engine.

```csharp
public RpcFilterManager()
```

## Properties

### <a id="DSInternals_Win32_RpcFilters_RpcFilterManager_IsAuditParametersSupported"></a> IsAuditParametersSupported

Indicates whether parameter buffer auditing is supported on the current operating system.

```csharp
public static bool IsAuditParametersSupported { get; }
```

#### Property Value

 [bool](https://learn.microsoft.com/dotnet/api/system.boolean)

#### Remarks

Parameter buffer auditing support was added in Windows 11 25H2 (10.0.26200).

### <a id="DSInternals_Win32_RpcFilters_RpcFilterManager_IsIpAddressFilterWithNamedPipesSupported"></a> IsIpAddressFilterWithNamedPipesSupported

Indicates whether the IP address filter conditions work with RPC over named pipes on the current operating system.

```csharp
public static bool IsIpAddressFilterWithNamedPipesSupported { get; }
```

#### Property Value

 [bool](https://learn.microsoft.com/dotnet/api/system.boolean)

#### Remarks

IP address filter support for RPC over named pipes was added in Windows 11 25H2 (10.0.26200).

### <a id="DSInternals_Win32_RpcFilters_RpcFilterManager_IsOpnumFilterSupported"></a> IsOpnumFilterSupported

Indicates whether the RPC OpNum filter condition is supported on the current operating system.

```csharp
public static bool IsOpnumFilterSupported { get; }
```

#### Property Value

 [bool](https://learn.microsoft.com/dotnet/api/system.boolean)

#### Remarks

The FWPM_CONDITION_RPC_OPNUM filter condition is supported since Windows 11 24H2 or Windows Server 2025 (10.0.26100).

## Methods

### <a id="DSInternals_Win32_RpcFilters_RpcFilterManager_AddFilter_DSInternals_Win32_RpcFilters_RpcFilter_"></a> AddFilter\(RpcFilter\)

Adds a new filter object to the system.

```csharp
public ulong AddFilter(RpcFilter filter)
```

#### Parameters

`filter` [RpcFilter](DSInternals.Win32.RpcFilters.RpcFilter.md)

The filter object to be added.

#### Returns

 [ulong](https://learn.microsoft.com/dotnet/api/system.uint64)

The runtime identifier for the newly created filter.

#### Exceptions

 [InvalidOperationException](https://learn.microsoft.com/dotnet/api/system.invalidoperationexception)

 [ArgumentNullException](https://learn.microsoft.com/dotnet/api/system.argumentnullexception)

 [ArgumentOutOfRangeException](https://learn.microsoft.com/dotnet/api/system.argumentoutofrangeexception)

 [PlatformNotSupportedException](https://learn.microsoft.com/dotnet/api/system.platformnotsupportedexception)

### <a id="DSInternals_Win32_RpcFilters_RpcFilterManager_Dispose"></a> Dispose\(\)

Closes the session to the filter engine.

```csharp
public void Dispose()
```

### <a id="DSInternals_Win32_RpcFilters_RpcFilterManager_GetFilters_System_Nullable_System_Guid__"></a> GetFilters\(Guid?\)

Retrieves a list of RPC filters from the system.

```csharp
public IEnumerable<RpcFilter> GetFilters(Guid? providerKey = null)
```

#### Parameters

`providerKey` [Guid](https://learn.microsoft.com/dotnet/api/system.guid)?

Unique identifier of the provider associated with the filters to be returned.

#### Returns

 [IEnumerable](https://learn.microsoft.com/dotnet/api/system.collections.generic.ienumerable\-1)<[RpcFilter](DSInternals.Win32.RpcFilters.RpcFilter.md)\>

List of RPC filters.

#### Exceptions

 [InvalidOperationException](https://learn.microsoft.com/dotnet/api/system.invalidoperationexception)

### <a id="DSInternals_Win32_RpcFilters_RpcFilterManager_RemoveFilter_System_UInt64_"></a> RemoveFilter\(ulong\)

Removes a filter object from the system.

```csharp
public void RemoveFilter(ulong id)
```

#### Parameters

`id` [ulong](https://learn.microsoft.com/dotnet/api/system.uint64)

Runtime identifier for the object being removed from the system.

#### Exceptions

 [InvalidOperationException](https://learn.microsoft.com/dotnet/api/system.invalidoperationexception)

