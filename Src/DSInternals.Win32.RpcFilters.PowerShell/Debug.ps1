<#
.SYNOPSIS
    Debugging script for the DSInternals.RpcFilters PowerShell module.
.PARAMETER ModulePath
    Path to the compiled PowerShell module
#>

#Requires -Version 5.1

[CmdletBinding(DefaultParameterSetName = 'Configuration')]
param(
    [Parameter(Mandatory = $false, ParameterSetName = 'ModulePath')]
    [ValidateNotNullOrEmpty()]
    [string] $ModulePath,

    [Parameter(Mandatory = $false, ParameterSetName = 'Configuration')]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Debug'
)

if ([string]::IsNullOrWhiteSpace($ModulePath)) {
    # No path has been provided, so use a the default value
    $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath "..\..\Build\bin\DSInternals.Win32.RpcFilters.PowerShell\$Configuration\DSInternals.RpcFilters" -Resolve -ErrorAction Stop
} else {
    [bool] $isFile = Test-Path -Path $ModulePath -PathType Leaf -ErrorAction SilentlyContinue
    if ($isFile) {
        # This is probably the module manifest path
        # Get the path to the module directory, without the trailing slash
        $ModulePath = Split-Path -Path $ModulePath -Parent -Resolve -ErrorAction Stop
    } else {
        # Translate possibly relative module directory path to an absolute one
        $ModulePath = Resolve-Path -Path $ModulePath -ErrorAction Stop
    }
}

# Load the compiled module
Import-Module -Name $ModulePath -Force -Verbose -ErrorAction Stop

# Clear the command prompt
function prompt() { 'PS > ' }

# Execute a cmdlet from the module
Get-RpcFilter
