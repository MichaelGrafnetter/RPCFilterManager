---
external help file: DSInternals.Win32.RpcFilters.PowerShell.dll-Help.xml
Module Name: DSInternals.RpcFilters
online version: https://github.com/MichaelGrafnetter/RPCFilterManager/blob/main/Documentation/PowerShell/Get-RpcFilter.md
schema: 2.0.0
---

# Get-RpcFilter

## SYNOPSIS
Gets a list of RPC filters that match the specified criteria.

## SYNTAX

### Default (Default)
```
Get-RpcFilter [[-ProviderKey] <Guid>] [<CommonParameters>]
```

### ZeroNetworks
```
Get-RpcFilter [-ZeroNetworks] [<CommonParameters>]
```

## DESCRIPTION
This cmdlet retrieves a list of RPC filters that match the specified criteria. If no criteria are specified, all RPC filters on the local computer are returned.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-RpcFilter
```

Retrieves all RPC filters on the local computer.

### Example 2
```powershell
PS C:\> Get-RpcFilter | Out-GridView
```

Displays all RPC filters in an interactive grid view.

## PARAMETERS

### -ProviderKey
Specifies the unique identifier of the RPC filter provider.

```yaml
Type: Guid
Parameter Sets: Default
Aliases: Provider, ProviderId, RpcFilterProvider, RpcFilterProviderId

Required: False
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ZeroNetworks
Specifies that only RPC filters created by the Zero Networks RPC Firewall should be returned. This parameter is equivalent to specifying the provider key 17171717-1717-1717-1717-171717171717, which is the unique identifier of the Zero Networks RPC Filter Provider.

```yaml
Type: SwitchParameter
Parameter Sets: ZeroNetworks
Aliases: RpcFirewall

Required: True
Position: 0
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### DSInternals.Win32.RpcFilters.RpcFilter
## NOTES

## RELATED LINKS

[Remove-RpcFilter](Remove-RpcFilter.md)
[New-RpcFilter](New-RpcFilter.md)
