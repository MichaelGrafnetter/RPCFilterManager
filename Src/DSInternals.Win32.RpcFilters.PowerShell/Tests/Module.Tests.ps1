<#
.SYNOPSIS
    Tests for the DSInternals.RpcFilters module.

.DESCRIPTION
    Administrative privileges are required for interacting with RPC filters.
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ModulePath = "..\..\..\Build\bin\DSInternals.Win32.RpcFilters.PowerShell\Release\DSInternals.RpcFilters"
)

BeforeDiscovery {
    Import-Module -Name $ModulePath -ErrorAction Stop -Force
}

Describe 'PowerShell Module' {
    Context 'Manifest' {
        BeforeAll {
            [string] $ModuleManifestPath = Join-Path $ModulePath DSInternals.RpcFilters.psd1
        }

        It 'exists' {
            $ModuleManifestPath | Should -Exist
        }

        It 'is valid' {
            Test-ModuleManifest -Path $ModuleManifestPath -ErrorAction Stop
        }
    }
}
