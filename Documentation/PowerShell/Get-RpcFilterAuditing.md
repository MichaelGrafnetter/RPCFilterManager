---
external help file: DSInternals.RpcFilters.Bootstrap-help.xml
Module Name: DSInternals.RpcFilters
online version: https://github.com/MichaelGrafnetter/RPCFilterManager/blob/main/Documentation/PowerShell/Get-RpcFilterAuditing.md
schema: 2.0.0
---

# Get-RpcFilterAuditing

## SYNOPSIS
Gets the current auditing settings for RPC events.

## SYNTAX

```
Get-RpcFilterAuditing [<CommonParameters>]
```

## DESCRIPTION
This cmdlet retrieves the current auditing settings for RPC events on the local machine.
It provides information about whether auditing is enabled or disabled for RPC-related activities, helping administrators monitor and manage RPC traffic effectively.

## EXAMPLES

### Example 1
```powershell
PS C:\> Get-RpcFilterAuditing
<# Sample Output:
Machine Name      : PC01
Policy Target     : System
Subcategory       : RPC Events
Subcategory GUID  : {0CCE922E-69AE-11D9-BED3-505054503030}
Inclusion Setting : No Auditing
Exclusion Setting :
#>
```

Gets the current auditing settings for RPC events on the local machine.

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### System.Management.Automation.PSObject
## NOTES

## RELATED LINKS

[Enable-RpcFilterAuditing](Enable-RpcFilterAuditing.md)
