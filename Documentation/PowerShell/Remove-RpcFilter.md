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
This cmdlet removes an existing RPC filter from the system. The filter can be specified by its unique identifier or by passing the filter object directly.

## EXAMPLES

### Example 1
```powershell
PS C:\> Remove-RpcFilter -Id 123
```

Removes the RPC filter with the specified identifier.

### Example 2
```powershell
PS C:\> Get-RpcFilter | where Name -eq 'Block-EFSRPC' | Remove-RpcFilter -PassThrough
```

Removes RPC filters called 'Block-EFSRPC' and returns the deleted filter objects.

### Example 3
```powershell
PS C:\> Get-RpcFilter | Remove-RpcFilter
```

Removes all existing RPC filters from the system.

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
If this switch is specified, the cmdlet returns the deleted RPC filter object. By default, this cmdlet does not generate any output.

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
