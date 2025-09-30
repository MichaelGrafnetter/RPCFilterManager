# <a id="DSInternals_Win32_RpcFilters_RpcFilterAction"></a> Enum RpcFilterAction

Namespace: [DSInternals.Win32.RpcFilters](DSInternals.Win32.RpcFilters.md)  
Assembly: DSInternals.Win32.RpcFilters.dll  

RPC filter action type.

```csharp
public enum RpcFilterAction : uint
```

## Fields

`Block = 4097` 

Block the traffic.



`CalloutInspection = 24580` 

Invoke a callout that never returns block or permit.



`CalloutTerminating = 20483` 

Invoke a callout that always returns block or permit.



`CalloutUnknown = 16389` 

Invoke a callout that may return block or permit.



`Permit = 4098` 

Permit the traffic.



