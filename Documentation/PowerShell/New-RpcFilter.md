---
external help file: DSInternals.Win32.RpcFilters.PowerShell.dll-Help.xml
Module Name: DSInternals.RpcFilters
online version:
schema: 2.0.0
---

# New-RpcFilter

## SYNOPSIS
{{ Fill in the Synopsis }}

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
{{ Fill Action Description }}

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
{{ Fill Audit Description }}

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
{{ Fill AuthenticationLevel Description }}

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
{{ Fill AuthenticationType Description }}

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
{{ Fill BootTimeEnforced Description }}

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
{{ Fill DcomAppId Description }}

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
{{ Fill Description Description }}

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
{{ Fill FilterKey Description }}

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
{{ Fill ImageName Description }}

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
{{ Fill InterfaceUUID Description }}

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
{{ Fill LocalAddress Description }}

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
{{ Fill LocalAddressMask Description }}

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
{{ Fill LocalPort Description }}

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
{{ Fill Name Description }}

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
{{ Fill NamedPipe Description }}

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
{{ Fill OperationNumber Description }}

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
{{ Fill PassThrough Description }}

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
{{ Fill Persistent Description }}

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
{{ Fill ProtocolSequence Description }}

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
{{ Fill ProviderKey Description }}

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
{{ Fill RemoteAddress Description }}

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
{{ Fill RemoteAddressMask Description }}

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
{{ Fill SecurityDescriptor Description }}

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
{{ Fill Weight Description }}

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
