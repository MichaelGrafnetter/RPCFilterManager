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

# Export cmdlets
Export-ModuleMember -Cmdlet 'Get-RpcFilter','New-RpcFilter','Remove-RpcFilter'
