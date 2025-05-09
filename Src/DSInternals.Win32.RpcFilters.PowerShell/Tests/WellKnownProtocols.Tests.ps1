<#
.SYNOPSIS
    Tests for the DSInternals.RpcFilters well-known protocol and operation translalion.
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ModulePath = "..\..\..\Build\bin\DSInternals.Win32.RpcFilters.PowerShell\Release\DSInternals.RpcFilters"
)

BeforeDiscovery {
    Import-Module -Name $ModulePath -ErrorAction Stop -Force
}

Describe 'Well-Known Protocols' {
    Context 'Protocol Enumeration' {
        BeforeDiscovery {
            [hashtable[]] $wellKnownProtocolNames =
                [Enum]::GetNames([DSInternals.Win32.RpcFilters.WellKnownProtocol]) |
                ForEach-Object { @{ Protocol = $PSItem } }
        }

        It '<Protocol> can be translated to UUID' -TestCases $wellKnownProtocolNames {
            param([string] $Protocol)
            # Throws an exception if the protocol cannot be translated
            [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator]::ToInterfaceUUID($Protocol)
        }
    }

    Context 'Operation Enumeration' {
        BeforeDiscovery {
            [hashtable[]] $wellKnownOperationNames =
                [Enum]::GetNames([DSInternals.Win32.RpcFilters.WellKnownOperation]) |
                ForEach-Object { @{ Operation = $PSItem } }
        }

        It '<Operation> can be translated to OpNum' -TestCases $wellKnownOperationNames {
            param([string] $Operation)
            # Throws an exception if the operation cannot be translated
            [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator]::ToOperationNumber($Operation)
        }
    }

    Context 'InterfaceUUID' {
        BeforeDiscovery {
            [hashtable[]] $wellKnownProtocolUUIDs =
                [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator].GetFields() |
                Where-Object FieldType -EQ ([guid]) |
                ForEach-Object { @{ Name = $PSItem.Name; UUID = [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator]::$($PSItem.Name) } }
        }

        It '<UUID> can be translated to <Name> protocol name' -TestCases $wellKnownProtocolUUIDs {
            param([string] $Name, [guid] $UUID)
            # Check if each interface UUID can be translated to a different string value
            [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator]::ToProtocolName($UUID) | Should -Not -Be $UUID
        }

        It 'unknown UUID should be translated to itself' {
            [guid] $unknown = New-Guid
            [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator]::ToProtocolName($unknown) | Should -Be $unknown
        }
    }
}
