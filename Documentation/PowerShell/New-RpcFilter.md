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
 -Action <RpcFilterAction> [-Audit] [-AuthenticationLevel <RpcAuthenticationLevel>]
 [-AuthenticationLevelMatchType <NumericMatchType>] [-AuthenticationType <RpcAuthenticationType>]
 [-Transport <RpcProtocolSequence>] [-SecurityDescriptor <RawSecurityDescriptor>]
 [-SecurityDescriptorNegativeMatch] [-RemoteAddress <IPAddress>] [-RemoteAddressMask <Byte>]
 [-LocalAddress <IPAddress>] [-LocalAddressMask <Byte>] [-LocalPort <UInt16>] [-Weight <UInt64>]
 [-OperationNumber <UInt16>] [<CommonParameters>]
```

### WellKnownProtocol
```
New-RpcFilter [-PassThrough] [-BootTimeEnforced] [-Persistent] [-Name <String>] [-Description <String>]
 [-ImageName <String>] [-NamedPipe <String>] [-FilterKey <Guid>] [-DcomAppId <Guid>]
 -WellKnownProtocol <WellKnownProtocol> -Action <RpcFilterAction> [-Audit]
 [-AuthenticationLevel <RpcAuthenticationLevel>] [-AuthenticationLevelMatchType <NumericMatchType>]
 [-AuthenticationType <RpcAuthenticationType>] [-Transport <RpcProtocolSequence>]
 [-SecurityDescriptor <RawSecurityDescriptor>] [-SecurityDescriptorNegativeMatch] [-RemoteAddress <IPAddress>]
 [-RemoteAddressMask <Byte>] [-LocalAddress <IPAddress>] [-LocalAddressMask <Byte>] [-LocalPort <UInt16>]
 [-Weight <UInt64>] [-OperationNumber <UInt16>] [<CommonParameters>]
```

### WellKnownOperation
```
New-RpcFilter [-PassThrough] [-BootTimeEnforced] [-Persistent] [-Name <String>] [-Description <String>]
 [-ImageName <String>] [-NamedPipe <String>] [-FilterKey <Guid>] [-DcomAppId <Guid>]
 -WellKnownOperation <WellKnownOperation> -Action <RpcFilterAction> [-Audit]
 [-AuthenticationLevel <RpcAuthenticationLevel>] [-AuthenticationLevelMatchType <NumericMatchType>]
 [-AuthenticationType <RpcAuthenticationType>] [-Transport <RpcProtocolSequence>]
 [-SecurityDescriptor <RawSecurityDescriptor>] [-SecurityDescriptorNegativeMatch] [-RemoteAddress <IPAddress>]
 [-RemoteAddressMask <Byte>] [-LocalAddress <IPAddress>] [-LocalAddressMask <Byte>] [-LocalPort <UInt16>]
 [-Weight <UInt64>] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet creates a new RPC filter for managing remote procedure call (RPC) traffic based on specified criteria. The filter can be customized using various parameters to define its behavior and conditions.

## EXAMPLES

### Example 1
```powershell
PS C:\> New-RpcFilter -Name 'Block-SCMR-NP' -Description 'Block MS-SCMR over Named Pipes' -WellKnownProtocol ServiceControlManager -Transport ncacn_np -Action Block -Audit
```

Creates a new RPC filter to block and audit service management (MS-SCMR) traffic over Named Pipes.

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
Aliases: AuthLevel
Accepted values: Default, None, Connect, Call, Packet, PacketIntegrity, PacketPrivacy

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -AuthenticationLevelMatchType
The match type (operator) for the authentication level.

```yaml
Type: NumericMatchType
Parameter Sets: (All)
Aliases: AuthLevelMatch, AuthLevelMatchType, AuthenticationLevelMatch

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
Aliases: AuthType
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
Aliases: Pipe, PipeName

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

### -RemoteAddress
The remote IP address.

```yaml
Type: IPAddress
Parameter Sets: (All)
Aliases: IPAddress, Address

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
Aliases: Mask, PrefixLength, Prefix, RemoteAddressPrefix, RemoteAddressPrefixLength

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

### -SecurityDescriptorNegativeMatch
Indicates whether to match the security descriptor negatively (i.e., NOT match).

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: PermissionsNegativeMatch, SecurityDescriptorNegate, PermissionsNegate

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Transport
Protocol family used by the RPC endpoint.

```yaml
Type: RpcProtocolSequence
Parameter Sets: (All)
Aliases: ProtSeq, Binding, ProtocolSequence

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
Aliases: WeightRange

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -WellKnownOperation
Specifies a well-known RPC operation. The protocol UUID and operation number is derived from the specified value.

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
Specifies a well-known RPC protocol. The protocol UUID is derived from the specified value.

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

[Get-RpcFilter](Get-RpcFilter.md)
[Remove-RpcFilter](Remove-RpcFilter.md)
[Get-RpcFilterEvent](Get-RpcFilterEvent.md)
