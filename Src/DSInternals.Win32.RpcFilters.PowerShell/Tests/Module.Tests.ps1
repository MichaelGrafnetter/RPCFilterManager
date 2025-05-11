<#
.SYNOPSIS
    Tests for the DSInternals.RpcFilters module.

.DESCRIPTION
    Administrative privileges are required for interacting with RPC filters.
.PARAMETER ModulePath
    Path to the compiled module directory.
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ModulePath
)

if ([string]::IsNullOrWhiteSpace($ModulePath)) {
    # No path has been provided, so use a the default value
    $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\..\Build\bin\DSInternals.Win32.RpcFilters.PowerShell\Release\DSInternals.RpcFilters' -Resolve -ErrorAction Stop
}

BeforeDiscovery {
    Import-Module -Name $ModulePath -ErrorAction Stop -Force
}

Describe 'PowerShell Module' {
    Context 'Manifest' {
        BeforeAll {
            [string] $ModuleManifestPath = Join-Path -Path $ModulePath -ChildPath 'DSInternals.RpcFilters.psd1'
        }

        It 'exists' {
            $ModuleManifestPath | Should -Exist
        }

        It 'is valid' {
            Test-ModuleManifest -Path $ModuleManifestPath -ErrorAction Stop
        }
    }
}
