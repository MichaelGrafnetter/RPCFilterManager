<#
.SYNOPSIS
    Debugging script for the DSInternals.RpcFilters PowerShell module.
#>

#Requires -Version 5.1

param(
    [Parameter(Mandatory = $true)]
    [string] $ModulePath
)

# Load the compiled module
Import-Module -Name $ModulePath -Force -Verbose -ErrorAction Stop

# Clear the command prompt
function prompt() { 'PS > ' }

# Execute a cmdlet from the module
Get-RpcFilter
