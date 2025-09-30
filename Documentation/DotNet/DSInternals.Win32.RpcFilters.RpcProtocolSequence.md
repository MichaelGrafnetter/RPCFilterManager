# <a id="DSInternals_Win32_RpcFilters_RpcProtocolSequence"></a> Enum RpcProtocolSequence

Namespace: [DSInternals.Win32.RpcFilters](DSInternals.Win32.RpcFilters.md)  
Assembly: DSInternals.Win32.RpcFilters.dll  

Microsoft RPC protocol sequences supported by the Windows Filtering Platform.

```csharp
public enum RpcProtocolSequence : uint
```

## Fields

`ncacn_http = 4` 

Connection-oriented TCP/IP using Microsoft Internet Information Server as HTTP proxy.



`ncacn_ip_tcp = 1` 

Connection-oriented Transmission Control Protocol/Internet Protocol (TCP/IP).



`ncacn_np = 2` 

Connection-oriented named pipes.



`ncalrpc = 3` 

Local procedure call.



