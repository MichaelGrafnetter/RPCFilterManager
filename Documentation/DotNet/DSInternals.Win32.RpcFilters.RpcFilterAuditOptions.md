# <a id="DSInternals_Win32_RpcFilters_RpcFilterAuditOptions"></a> Enum RpcFilterAuditOptions

Namespace: [DSInternals.Win32.RpcFilters](DSInternals.Win32.RpcFilters.md)  
Assembly: DSInternals.Win32.RpcFilters.dll  

Audit options for RPC filters.

```csharp
[Flags]
public enum RpcFilterAuditOptions : ulong
```

## Fields

`Disabled = 0` 

Auditing is disabled for this filter.



`Enabled = 1` 

Auditing is enabled for this filter.



`EnabledWithParams = 3` 

Auditing with parameters is enabled for this filter.



`Parameters = 2` 

Parameter buffer auditing is enabled for this filter.

This flag can only be set if auditing is also enabled.

