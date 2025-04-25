---
external help file: DSInternals.Win32.RpcFilters.PowerShell.dll-Help.xml
Module Name: DSInternals.RpcFilters
online version: https://github.com/MichaelGrafnetter/RPCFilterManager/blob/main/Documentation/PowerShell/New-RpcFilter.md
schema: 2.0.0
---

# New-RpcFilter

## SYNOPSIS
Creates a new RPC filter for managing remote procedure call (RPC) traffic based on specified criteria.

## SYNTAX

### CustomProtocol (Default)
```
New-RpcFilter [-PassThrough] [-BootTimeEnforced] [-Persistent] [-Name <String>] [-Description <String>]
 [-ImageName <String>] [-NamedPipe <String>] [-FilterKey <Guid>] [-DcomAppId <Guid>] [-InterfaceUUID <Guid>]
 [-ProviderKey <Guid>] -Action <RpcFilterAction> [-Audit] [-AuthenticationLevel <RpcAuthenticationLevel>]
 [-AuthenticationType <RpcAuthenticationType>] [-ProtocolSequence <RpcProtocolSequence>]
 [-SecurityDescriptor <RawSecurityDescriptor>] [-RemoteAddress <IPAddress>] [-RemoteAddressMask <Byte>]
 [-LocalAddress <IPAddress>] [-LocalAddressMask <Byte>] [-LocalPort <UInt16>] [-Weight <UInt64>]
 [-OperationNumber <UInt16>] [<CommonParameters>]
```

### WellKnownProtocol
```
New-RpcFilter [-PassThrough] [-BootTimeEnforced] [-Persistent] [-Name <String>] [-Description <String>]
 [-ImageName <String>] [-NamedPipe <String>] [-FilterKey <Guid>] [-DcomAppId <Guid>]
 -WellKnownProtocol <WellKnownProtocol> [-ProviderKey <Guid>] -Action <RpcFilterAction> [-Audit]
 [-AuthenticationLevel <RpcAuthenticationLevel>] [-AuthenticationType <RpcAuthenticationType>]
 [-ProtocolSequence <RpcProtocolSequence>] [-SecurityDescriptor <RawSecurityDescriptor>]
 [-RemoteAddress <IPAddress>] [-RemoteAddressMask <Byte>] [-LocalAddress <IPAddress>]
 [-LocalAddressMask <Byte>] [-LocalPort <UInt16>] [-Weight <UInt64>] [-OperationNumber <UInt16>]
 [<CommonParameters>]
```

### WellKnownOperation
```
New-RpcFilter [-PassThrough] [-BootTimeEnforced] [-Persistent] [-Name <String>] [-Description <String>]
 [-ImageName <String>] [-NamedPipe <String>] [-FilterKey <Guid>] [-DcomAppId <Guid>]
 -WellKnownOperation <WellKnownOperation> [-ProviderKey <Guid>] -Action <RpcFilterAction> [-Audit]
 [-AuthenticationLevel <RpcAuthenticationLevel>] [-AuthenticationType <RpcAuthenticationType>]
 [-ProtocolSequence <RpcProtocolSequence>] [-SecurityDescriptor <RawSecurityDescriptor>]
 [-RemoteAddress <IPAddress>] [-RemoteAddressMask <Byte>] [-LocalAddress <IPAddress>]
 [-LocalAddressMask <Byte>] [-LocalPort <UInt16>] [-Weight <UInt64>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -Action
Specifies the action to be performed if all the filter conditions are true.

```yaml
Type: RpcFilterAction
Parameter Sets: (All)
Aliases:
Accepted values: Block, Permit, CalloutUnknown, CalloutTerminating, CalloutInspection

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Audit
Indicates whether incoming RPC calls are audited as part of C2 and common criteria compliance.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -AuthenticationLevel
The authentication level controls how much security a client or server wants from its SSP.

```yaml
Type: RpcAuthenticationLevel
Parameter Sets: (All)
Aliases:
Accepted values: Default, None, Connect, Call, Packet, PacketIntegrity, PacketPrivacy

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -AuthenticationType
Authentication service used for RPC connections.

```yaml
Type: RpcAuthenticationType
Parameter Sets: (All)
Aliases:
Accepted values: None, Negotiate, NTLM, SChannel, Kerberos, Digest, Default

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -BootTimeEnforced
Indicates whether the filter is enforced at boot-time, even before BFE starts.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: Boot

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DcomAppId
The identification of the COM application.

```yaml
Type: Guid
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Description
Optional filter description.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -FilterKey
Unique identifier of the filter.

```yaml
Type: Guid
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -ImageName
The name of the application.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -InterfaceUUID
The UUID of the RPC interface.

```yaml
Type: Guid
Parameter Sets: CustomProtocol
Aliases: RpcProtocol, Protocol, ProtocolUUID

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -LocalAddress
The local IP address.

```yaml
Type: IPAddress
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -LocalAddressMask
The local IP address mask.

```yaml
Type: Byte
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -LocalPort
The local transport protocol port number.

```yaml
Type: UInt16
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Name
Human-readable RPC filter name.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -NamedPipe
The name of the remote named pipe.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -OperationNumber
The RPC operation number for an RPC call made to an RPC listener.

```yaml
Type: UInt16
Parameter Sets: CustomProtocol, WellKnownProtocol
Aliases: OpNum

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -PassThrough
Indicates whether to return the object that was created by the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Persistent
Indicates whether the filter is persistent, that is, it survives across BFE stop/start.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProtocolSequence
Protocol family used by the RPC endpoint.

```yaml
Type: RpcProtocolSequence
Parameter Sets: (All)
Aliases: ProtSeq, Binding, Transport
Accepted values: ncacn_ip_tcp, ncacn_np, ncalrpc, ncacn_http

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -ProviderKey
Optional identifier of the policy provider that manages this filter.

```yaml
Type: Guid
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -RemoteAddress
The remote IP address.

```yaml
Type: IPAddress
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -RemoteAddressMask
The remote IP address mask.

```yaml
Type: Byte
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -SecurityDescriptor
The identification of the remote user in SDDL form.

```yaml
Type: RawSecurityDescriptor
Parameter Sets: (All)
Aliases: SDDL, Permissions, DACL

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Weight
The weight indicates the priority of the filter, where higher-numbered weights have higher priorities.

```yaml
Type: UInt64
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -WellKnownOperation
{{ Fill WellKnownOperation Description }}

```yaml
Type: WellKnownOperation
Parameter Sets: WellKnownOperation
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -WellKnownProtocol
{{ Fill WellKnownProtocol Description }}

```yaml
Type: WellKnownProtocol
Parameter Sets: WellKnownProtocol
Aliases: WellKnownInterface

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String
### System.Nullable`1[[System.Guid, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]
### DSInternals.Win32.RpcFilters.RpcFilterAction
### System.Management.Automation.SwitchParameter
### System.Nullable`1[[DSInternals.Win32.RpcFilters.RpcAuthenticationLevel, DSInternals.Win32.RpcFilters, Version=1.0.0.0, Culture=neutral, PublicKeyToken=af7e77ba04a3c166]]
### System.Nullable`1[[DSInternals.Win32.RpcFilters.RpcAuthenticationType, DSInternals.Win32.RpcFilters, Version=1.0.0.0, Culture=neutral, PublicKeyToken=af7e77ba04a3c166]]
### System.Nullable`1[[DSInternals.Win32.RpcFilters.RpcProtocolSequence, DSInternals.Win32.RpcFilters, Version=1.0.0.0, Culture=neutral, PublicKeyToken=af7e77ba04a3c166]]
### System.Security.AccessControl.RawSecurityDescriptor
### System.Net.IPAddress
### System.Nullable`1[[System.Byte, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]
### System.Nullable`1[[System.UInt16, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]
### System.Nullable`1[[System.UInt64, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]
## OUTPUTS

### DSInternals.Win32.RpcFilters.RpcFilter
## NOTES

## RELATED LINKS

[Test-RpcFilterOpNumSupport](Test-RpcFilterOpNumSupport.md)
[Get-RpcFilter](Get-RpcFilter.md)
[Remove-RpcFilter](Remove-RpcFilter.md)
