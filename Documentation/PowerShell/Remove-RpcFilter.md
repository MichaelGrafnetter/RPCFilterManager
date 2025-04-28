---
external help file: DSInternals.Win32.RpcFilters.PowerShell.dll-Help.xml
Module Name: DSInternals.RpcFilters
online version: https://github.com/MichaelGrafnetter/RPCFilterManager/blob/main/Documentation/PowerShell/Remove-RpcFilter.md
schema: 2.0.0
---

# Remove-RpcFilter

## SYNOPSIS
Removes an existing remote procedure call (RPC) filter.

## SYNTAX

### Id (Default)
```
Remove-RpcFilter [-Id] <UInt64> [<CommonParameters>]
```

### InputObject
```
Remove-RpcFilter [-InputObject] <RpcFilter> [-PassThrough] [<CommonParameters>]
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

### -Id
Specifies the identifier of the RPC filter to delete.

```yaml
Type: UInt64
Parameter Sets: Id
Aliases: FilterId, RpcFilter

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -InputObject
Specifies the RPC filter object to delete.

```yaml
Type: RpcFilter
Parameter Sets: InputObject
Aliases: Filter

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -PassThrough
{{ Fill PassThrough Description }}

```yaml
Type: SwitchParameter
Parameter Sets: InputObject
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.UInt64
### DSInternals.Win32.RpcFilters.RpcFilter
## OUTPUTS

### None
## NOTES

## RELATED LINKS
