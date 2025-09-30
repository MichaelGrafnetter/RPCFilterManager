# <a id="DSInternals_Win32_RpcFilters_RpcAuthenticationLevel"></a> Enum RpcAuthenticationLevel

Namespace: [DSInternals.Win32.RpcFilters](DSInternals.Win32.RpcFilters.md)  
Assembly: DSInternals.Win32.RpcFilters.dll  

The authentication level controls how much security a client or server wants from its SSP.

```csharp
public enum RpcAuthenticationLevel : uint
```

## Fields

`Call = 3` 

Only the headers of the beginning of each call are signed.



`Connect = 2` 

The normal authentication handshake occurs between the client and server, and a session key is established but that key is never used for communication between the client and server.



`Default = 0` 

COM chooses the authentication level by using its normal security blanket negotiation.



`None = 1` 

No authentication is performed during the communication between client and server.



`Packet = 4` 

The header of each packet is signed but not encrypted.



`PacketIntegrity = 5` 

Each packet of data is signed in its entirety but is not encrypted.



`PacketPrivacy = 6` 

Each data packet is signed and encrypted.



