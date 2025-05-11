<#
.SYNOPSIS
    Invokes Pester tests for the DSInternals.RpcFilters PowerShell module.
.PARAMETER ModulePath
    Path to the compiled PowerShell module
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ModulePath
)

if ([string]::IsNullOrWhiteSpace($ModulePath)) {
    # No path has been provided, so use a the default value
    $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\Build\bin\DSInternals.Win32.RpcFilters.PowerShell\Release\DSInternals.RpcFilters' -Resolve -ErrorAction Stop
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

# Load the required PowerShell modules
Import-Module -Name Pester -ErrorAction Stop

# Get rid of the long directory path in the command prompt
function prompt() { 'PS > ' }

# Invoke the tests
[PesterConfiguration] $config = [PesterConfiguration]::Default
$config.Run.Container = New-PesterContainer -Path $PSScriptRoot -Data @{
    ModulePath = $ModulePath # Compiled module directory
}
$config.Run.Path = $PSScriptRoot # Directory with the tests
$config.Output.Verbosity = 'Detailed'
$config.Output.StackTraceVerbosity = 'None'
$config.TestResult.Enabled = $true
$config.TestResult.OutputFormat = 'NUnitXml'
$config.TestResult.OutputPath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\Build\TestResults\Pester.xml'

Invoke-Pester -Configuration $config
