<#
.SYNOPSIS
    Tests for the DSInternals.RpcFilters well-known protocol and operation translalion.
.PARAMETER ModulePath
    Path to the compiled module directory.
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
    $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\..\Build\bin\DSInternals.Win32.RpcFilters.PowerShell\Release\DSInternals.RpcFilters' -Resolve -ErrorAction Stop
}

BeforeDiscovery {
    Import-Module -Name $ModulePath -ErrorAction Stop -Force
}

Describe 'Well-Known Protocols' {
    Context 'Protocol Enumeration' {
        BeforeDiscovery {
            [hashtable[]] $wellKnownProtocolNames =
                [Enum]::GetNames([DSInternals.Win32.RpcFilters.WellKnownProtocol]) |
                ForEach-Object { @{ Protocol = $PSItem } }

            [hashtable[]] $wellKnownProtocolUUIDs =
                [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator].GetFields() |
                Where-Object FieldType -EQ ([guid]) |
                ForEach-Object { @{ Name = $PSItem.Name; UUID = [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator]::$($PSItem.Name) } }
        }

        BeforeAll {
            [guid[]] $coveredUUIDs = [Enum]::GetNames([DSInternals.Win32.RpcFilters.WellKnownProtocol]) | ForEach-Object {
                try {
                    # Return the corresponding UUID for each protocol
                    [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator]::ToInterfaceUUID([DSInternals.Win32.RpcFilters.WellKnownProtocol]::$PSItem)
                } catch {
                    # Ignore protocols that cannot be translated, as this is covered in other tests
                }
            }
        }

        It '<Protocol> can be translated to UUID' -TestCases $wellKnownProtocolNames {
            param([string] $Protocol)

            # Throws an exception if the protocol cannot be translated
            [guid] $interfaceUUID = [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator]::ToInterfaceUUID($Protocol)
        }

        It 'has a member corresponding to <Name> (<UUID>)' -TestCases $wellKnownProtocolUUIDs {
            param([string] $Name, [guid] $UUID)

            if ($coveredUUIDs -notcontains $UUID -and $Name -like '*_*') {
                # Skip the test for interface with an underscore in their name (like DCOM_IObjectExporter) for now.
                Set-ItResult -Skipped -Because 'protocols with multiple interfaces are yet to be implemented.'
            } else {
                # Check if the UUID is covered by the protocol enumeration
                $coveredUUIDs | Should -Contain $UUID
            }
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

        It '<Operation> can be translated from OpNum' -TestCases $wellKnownOperationNames {
            param([string] $Operation)

            # Translate the well-known operation to OpNum
            $valueTuple = [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator]::ToOperationNumber($Operation)
            [DSInternals.Win32.RpcFilters.WellKnownProtocol] $protocol = $valueTuple.Item1
            [uint16] $operationNumber = $valueTuple.Item2

            [guid] $interfaceUUID = [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator]::ToInterfaceUUID($protocol)

            # Translate OpNum back to string
            [string] $operationName = [DSInternals.Win32.RpcFilters.WellKnownProtocolTranslator]::ToOperationName($interfaceUUID, $operationNumber)
            $operationName | Should -Be "$Operation ($operationNumber)"
        }
    }

    Context 'Interface UUID' {
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
