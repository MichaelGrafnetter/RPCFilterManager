<#
.SYNOPSIS
    Invokes Pester tests for the DSInternals.RpcFilters PowerShell module.
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

param(
    [Parameter(Mandatory = $true)]
    [string] $ModulePath
)

# Load the required PowerShell modules
Import-Module -Name Pester -ErrorAction Stop
Import-Module -Name $ModulePath -ErrorAction Stop

# Clear the command prompt
function prompt() { 'PS > ' }

# Invoke the tests
[PesterConfiguration] $config = [PesterConfiguration]::Default
$config.Run.Container = New-PesterContainer -Path $PSScriptRoot -Data @{
    ModulePath = $ModulePath
}
$config.Output.Verbosity = 'Detailed'
$config.Output.StackTraceVerbosity = 'None'

Invoke-Pester -Configuration $config
