---
external help file: DSInternals.RpcFilters.Bootstrap-help.xml
Module Name: DSInternals.RpcFilters
online version: https://github.com/MichaelGrafnetter/RPCFilterManager/blob/main/Documentation/PowerShell/Get-RpcFilterEvent.md
schema: 2.0.0
---

# Get-RpcFilterEvent

## SYNOPSIS
Gets RPC audit events from the Security log.

## SYNTAX

```
Get-RpcFilterEvent [[-ComputerName] <String>] [[-MaxEvents] <Int64>] [<CommonParameters>]
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

### -ComputerName
The name of the computer to query.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: Localhost
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -MaxEvents
The maximum number of events to retrieve.

```yaml
Type: Int64
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: 9223372036854775807
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS

[Enable-RpcFilterAuditing](Enable-RpcFilterAuditing.md)
[New-RpcFilter](New-RpcFilter.md)
