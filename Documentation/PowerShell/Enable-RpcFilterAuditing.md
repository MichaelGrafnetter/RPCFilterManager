---
external help file: DSInternals.RpcFilters.Bootstrap-help.xml
Module Name: DSInternals.RpcFilters
online version: https://github.com/MichaelGrafnetter/RPCFilterManager/blob/main/Documentation/PowerShell/Enable-RpcFilterAuditing.md
schema: 2.0.0
---

# Enable-RpcFilterAuditing

## SYNOPSIS
Enable security auditing for RPC events.

## SYNTAX

```
Enable-RpcFilterAuditing [<CommonParameters>]
```

## DESCRIPTION
This cmdlet enables security auditing for RPC events by configuring the appropriate audit policy settings on the local computer using the netsh tool.
The cmdlet must be run with elevated privileges.

## EXAMPLES

### Example 1
```powershell
PS C:\> Enable-RpcFilterAuditing
```

Enables security auditing for RPC events.

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### None
## NOTES

## RELATED LINKS

[Get-RpcFilterAuditing](Get-RpcFilterAuditing.md)
[Disable-RpcFilterAuditing](Disable-RpcFilterAuditing.md)
[Get-RpcFilterEvent](Get-RpcFilterEvent.md)
[New-RpcFilter](New-RpcFilter.md)
