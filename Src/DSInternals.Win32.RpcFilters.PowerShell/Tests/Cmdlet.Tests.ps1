<#
.SYNOPSIS
    Tests for the DSInternals.RpcFilters module cmdlets.
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

Describe 'Cmdlets' {
    Context 'New-RpcFilter' {
        It 'Get-RpcFilter returns a list of RpcFilter objects' {
            [string] $filterName = 'TestFilter'

            # No filters should initially be present
            Get-RpcFilter | Should -HaveCount 0
            New-RpcFilter -Name $filterName -Action Permit -InterfaceUUID ([guid]::NewGuid())

            try {
                # Check that the filter was created
                Get-RpcFilter | Should -HaveCount 1
            }
            finally {
                # Delete the filter
                Get-RpcFilter | Where-Object Name -eq $filterName | Remove-RpcFilter
            }

            Set-ItResult -Inconclusive -Because 'this test is not implemented yet.'
        }

    }

    Context 'Serialization' {
        It 'RpcFilter can be serialized to CLI XML' {
            # Create a new RpcFilter object that will be serialized and deserialized again
            [DSInternals.Win32.RpcFilters.RpcFilter] $filter = [DSInternals.Win32.RpcFilters.RpcFilter]::new()
            $filter.Name = 'TestFilter'
            $filter.InterfaceUUID = [guid]::NewGuid()

            [string] $tempFilePath = Join-Path -Path $env:TEMP -ChildPath 'RpcFilter.xml'
            Export-Clixml -InputObject $filter -Path $tempFilePath -Force
            try {
                [psobject] $deserialized = Import-Clixml -Path $tempFilePath
                $deserialized.Name | Should -Be $filter.Name
                $deserialized.InterfaceUUID | Should -Be $filter.InterfaceUUID
            }
            finally {
                # Make sure the temporary file gets deleted even if the test fails
                Remove-Item -Path $tempFilePath -Force
            }
        }

        It 'RpcEventLogRecord can be serialized to CLI XML' {
            Set-ItResult -Inconclusive -Because 'this test is not implemented yet.'
        }
    }
}
