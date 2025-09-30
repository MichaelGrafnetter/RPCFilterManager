# <a id="DSInternals_Win32_RpcFilters_RpcAuthenticationType"></a> Enum RpcAuthenticationType

Namespace: [DSInternals.Win32.RpcFilters](DSInternals.Win32.RpcFilters.md)  
Assembly: DSInternals.Win32.RpcFilters.dll  

Authentication service used for RPC connections.

```csharp
public enum RpcAuthenticationType : uint
```

## Fields

`Default = 4294967295` 

Use the default authentication service.



`Digest = 21` 

Use the Microsoft Digest SSP.



`Kerberos = 16` 

Use the Microsoft Kerberos SSP.



`NTLM = 10` 

Use the Microsoft NT LAN Manager (NTLM) SSP.



`Negotiate = 9` 

Use the Microsoft Negotiate SSP. This SSP negotiates between the use of the NTLM and Kerberos protocol Security Support Providers (SSP).



`None = 0` 

No authentication.



`SChannel = 14` 

Use the Schannel SSP. This SSP supports Secure Socket Layer (SSL), private communication technology (PCT), and transport level security (TLS).



