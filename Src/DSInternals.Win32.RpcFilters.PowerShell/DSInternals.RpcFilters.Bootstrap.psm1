#
# Script module file for the 'DSInternals.RpcFilters' module.
#
# Copyright (c) Michael Grafnetter
#

# Check if the current OS is Windows.
if ($env:OS -ne 'Windows_NT') {
    Write-Error -Message 'The DSInternals.RpcFilters PowerShell module is only supported on Windows.' `
                -Category ([System.Management.Automation.ErrorCategory]::NotImplemented)
}

# Load the platform-specific binaries.
# Note: This operation cannot be done in the module manifest,
#       as it only supports restricted language mode.
if ($PSVersionTable.PSVersion.Major -ge 6) {
    [string] $coreModulePath = "$PSScriptRoot/net8.0-windows/DSInternals.Win32.RpcFilters.PowerShell.dll"
    Import-Module -Name $coreModulePath -ErrorAction Stop
}
else {
    [string] $desktopModulePath = "$PSScriptRoot/net48/DSInternals.Win32.RpcFilters.PowerShell.dll"
    Import-Module -Name $desktopModulePath -ErrorAction Stop
}

#region Script cmdlets

<#
.SYNOPSIS
    Gets RPC audit events from the Security log.

.PARAMETER ComputerName
    The name of the computer to query.

.PARAMETER MaxEvents
    The maximum number of events to retrieve.

#>
function Get-RpcFilterEvent {
    [CmdletBinding()]
    [OutputType([DSInternals.Win32.RpcFilters.PowerShell.RpcEventLogRecord])]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ComputerName,

        [Parameter(Mandatory = $false)]
        [long] $MaxEvents = [long]::MaxValue
    )

    process {
        [hashtable] $computerNameParameter = @{}

        if ($null -ne $ComputerName) {
            # Use parameter splatting in order to support empty ComputerName
            # The Get-WinEvent command behaves slightly differently with "localhost" as ComputerName value.
            $computerNameParameter = @{ ComputerName = $ComputerName }
        }

        # Fetch the corresponding events and convert them to a human-readable format.
        Get-WinEvent @computerNameParameter -FilterHashtable @{
            LogName = 'Security'
            ProviderName = 'Microsoft-Windows-Security-Auditing'
            Id = '5712' # Event ID 5712: A Remote Procedure Call (RPC) was attempted.
        } -MaxEvents $MaxEvents | ForEach-Object { [DSInternals.Win32.RpcFilters.PowerShell.RpcEventLogRecord] $PSItem }
    }
}

<#
.SYNOPSIS
    Enables security auditing for RPC events.

#>
function Enable-RpcFilterAuditing {
    [CmdletBinding()]
    [OutputType('None')]
    param()

    # Run the native command and drop the output
    auditpol.exe /set /subcategory:"RPC Events" /success:enable /failure:enable > $null
}

<#
.SYNOPSIS
    Disables security auditing for RPC events.

#>
function Disable-RpcFilterAuditing {
    [CmdletBinding()]
    [OutputType('None')]
    param()

    # Run the native command and drop the output
    auditpol.exe /set /subcategory:"RPC Events" /success:disable /failure:disable > $null
}

<#
.SYNOPSIS
    Gets the current auditing settings for RPC events.

#>
function Get-RpcFilterAuditing {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    # Run the native command and convert the CSV output to objects
    auditpol.exe /get /subcategory:"RPC Events" /r | ConvertFrom-Csv -Delimiter ','
}

#endregion Script cmdlets

# Define cmdlet aliases
New-Alias -Name 'Add-RpcFilter' -Value 'New-RpcFilter' -Force

# Export cmdlets
Export-ModuleMember -Cmdlet @('Get-RpcFilter', 'New-RpcFilter', 'Remove-RpcFilter') `
                    -Alias @('Add-RpcFilter') `
                    -Function @('Get-RpcFilterEvent', 'Enable-RpcFilterAuditing', 'Disable-RpcFilterAuditing', 'Get-RpcFilterAuditing')
