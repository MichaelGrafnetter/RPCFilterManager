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
    [string] $desktopModulePath = "$PSScriptRoot/net480/DSInternals.Win32.RpcFilters.PowerShell.dll"
    Import-Module -Name $desktopModulePath -ErrorAction Stop
}

#region Script cmdlets

# Windows Event Auditing Success
[long] $SuccessKeyWord = 0x8020000000000000

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
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ComputerName = 'localhost',

        [Parameter(Mandatory = $false)]
        [long] $MaxEvents = [long]::MaxValue
    )

    process {
        # Fetch the corresponding events and convert them to a readable format.
        Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
            LogName = 'Security'
            ProviderName = 'Microsoft-Windows-Security-Auditing'
            Id = '5712' # Event ID 5712: A Remote Procedure Call (RPC) was attempted.
        } -MaxEvents $MaxEvents | Select-Object -Property @(
             'MachineName',
             'TimeCreated',
             @{n = 'Success'; e = { $PSItem.Keywords -eq $SuccessKeyWord }},
             @{n = 'UserName'; e = { $PSItem.Properties[1].Value }},
             @{n = 'DomainName'; e = { $PSItem.Properties[2].Value }},
             @{n = 'ProcessId'; e = { $PSItem.Properties[4].Value }},
             @{n = 'ProcessName'; e = { $PSItem.Properties[5].Value }},
             @{n = 'Protocol'; e = { [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator]::ToProtocolName($PSItem.Properties[8].Value) }},
             @{n = 'Transfer'; e = { [DSInternals.Win32.RpcFilters.RpcProtocolSequence] $PSItem.Properties[9].Value }},
             @{n = 'RemoteIPAddress'; e = { [ipaddress] $PSItem.Properties[6].Value }},
             @{n = 'RemotePort'; e = { [uint16] $PSItem.Properties[7].Value }},
             @{n = 'AuthenticationType'; e = { [DSInternals.Win32.RpcFilters.RpcAuthenticationType] $PSItem.Properties[10].Value }},
             @{n = 'AuthenticationLevel'; e = { [DSInternals.Win32.RpcFilters.RpcAuthenticationLevel] $PSItem.Properties[11].Value }}
        )
    }
}

<#
.SYNOPSIS
    Enables security auditing for RPC events.

#>
function Enable-RpcFilterAuditing {
    [CmdletBinding()]
    param()

    # Run the native command
    auditpol.exe /set /subcategory:"RPC Events" /success:enable /failure:enable
}

<#
.SYNOPSIS
    Disables security auditing for RPC events.

#>
function Disable-RpcFilterAuditing {
    [CmdletBinding()]
    param()

    # Run the native command
    auditpol.exe /set /subcategory:"RPC Events" /success:disable /failure:disable
}

#endregion Script cmdlets

# Define cmdlet aliases
New-Alias -Name 'Add-RpcFilter' -Value 'New-RpcFilter' -Force

# Export cmdlets
Export-ModuleMember -Cmdlet @('Get-RpcFilter', 'New-RpcFilter', 'Remove-RpcFilter') `
                    -Alias @('Add-RpcFilter') `
                    -Function @('Get-RpcFilterEvent', 'Enable-RpcFilterAuditing', 'Disable-RpcFilterAuditing')
