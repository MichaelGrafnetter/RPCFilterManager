---
external help file: DSInternals.RpcFilters.Bootstrap-help.xml
Module Name: DSInternals.RpcFilters
online version: https://github.com/MichaelGrafnetter/RPCFilterManager/blob/main/Documentation/PowerShell/Disable-RpcFilterAuditing.md
schema: 2.0.0
---

# Disable-RpcFilterAuditing

## SYNOPSIS
Disables security auditing for RPC events.

## SYNTAX

```
Disable-RpcFilterAuditing [<CommonParameters>]
```

## DESCRIPTION
This cmdlet disables security auditing for RPC events by configuring the appropriate audit policy settings on the local computer using the netsh tool.
The cmdlet must be run with elevated privileges.

## EXAMPLES

### Example 1
```powershell
PS C:\> Disable-RpcFilterAuditing
```

Disables security auditing for RPC events.

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### None
## NOTES

## RELATED LINKS

[Get-RpcFilterAuditing](Get-RpcFilterAuditing.md)
[Enable-RpcFilterAuditing](Enable-RpcFilterAuditing.md)
