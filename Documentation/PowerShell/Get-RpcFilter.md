---
external help file: DSInternals.Win32.RpcFilters.PowerShell.dll-Help.xml
Module Name: DSInternals.RpcFilters
online version:
schema: 2.0.0
---

# Get-RpcFilter

## SYNOPSIS
{{ Fill in the Synopsis }}

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
{{ Fill in the Description }}

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -ProviderKey
{{ Fill ProviderKey Description }}

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
{{ Fill ZeroNetworks Description }}

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
