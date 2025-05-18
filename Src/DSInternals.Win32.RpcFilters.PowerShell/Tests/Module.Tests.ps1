<#
.SYNOPSIS
    Tests for the DSInternals.RpcFilters module metadata.
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

Describe 'PowerShell Module' {
    Context 'Manifest' {
        BeforeAll {
            [string] $ModuleManifestPath = Join-Path -Path $ModulePath -ChildPath 'DSInternals.RpcFilters.psd1'
        }

        BeforeDiscovery {
            # Get a list of all files in the module directory, excluding .pdb and .psd1 files
            [hashtable[]] $BundledFiles =
                Get-ChildItem -Path $ModulePath -Recurse -File -Exclude *.pdb,*.psd1 |
                ForEach-Object { @{ FileName = $PSItem.Name } }

            [string] $bootstrapPath = Join-Path -Path $ModulePath -ChildPath 'DSInternals.RpcFilters.Bootstrap.psm1'

            [hashtable[]] $ModuleAliases =
                Select-String -Path $bootstrapPath -Pattern 'New-Alias -Name ([a-zA-Z\-]+) ' |
                ForEach-Object { @{ AliasName = $PSItem.Matches.Groups[1].Value } }
        }

        It 'exists' {
            $ModuleManifestPath | Should -Exist
        }

        It 'is valid' {
            Test-ModuleManifest -Path $ModuleManifestPath -ErrorAction Stop
        }

        It 'has the same version as the binary module' {
            # Load the .NET Framework assembly (skip .NET 5+)
            [string] $assemblyPath = Join-Path -Path $ModulePath -ChildPath 'net480\DSInternals.Win32.RpcFilters.PowerShell.dll'
            [System.Reflection.AssemblyName] $assembly = [System.Reflection.AssemblyName]::GetAssemblyName($assemblyPath)

            # Load the module manifest
            [hashtable] $manifest =  Import-PowerShellDataFile -Path $ModuleManifestPath
            [version] $moduleVersion = [version]::Parse($manifest.ModuleVersion)
            # Parser uses -1 instead of 0 for unused numbers, so we need to fix that
            if ($moduleVersion.Build -eq -1) {
                $moduleVersion = [version]::new($moduleVersion.Major, $moduleVersion.Minor, 0, 0)
            } else {
                $moduleVersion = [version]::new($moduleVersion.Major, $moduleVersion.Minor, $moduleVersion.Build, 0)
            }
            # Compare their versions
            $moduleVersion | Should -BeExactly $assembly.Version
        }

        It 'references the <FileName> file.' -TestCases $BundledFiles -Test {
            param([string] $FileName)

            $ModuleManifestPath | Should -FileContentMatch $FileName
        }

        It 'exports alias <AliasName>.' -TestCases $ModuleAliases -Test {
            param([string] $AliasName)

            $moduleManifestPath | Should -FileContentMatch "'$AliasName'"
        }
    }

    Context 'Directory Structure' {
        It 'does not contain .NET XML documentation' {
            Get-ChildItem -Path $ModulePath -Recurse -Filter '*.xml' -Exclude '*-Help.xml' | Should -HaveCount 0
        }

        It 'does not contain dependency files' {
            Get-ChildItem -Path $ModulePath -Recurse -Filter '*.deps.json' | Should -HaveCount 0
        }

        It 'contains MAML help' {
            Join-Path -Path $ModulePath -ChildPath 'en-US\DSInternals.RpcFilters.Bootstrap-help.xml' | Should -Exist
            Join-Path -Path $ModulePath -ChildPath 'en-US\DSInternals.Win32.RpcFilters.PowerShell.dll-Help.xml' | Should -Exist
        }

        It 'contains an About topic' {
            Join-Path -Path $ModulePath -ChildPath 'en-US\about_DSInternals.RpcFilters.help.txt' | Should -Exist
        }
    }

    Context 'Views' {
        BeforeDiscovery {
            # Get all .NET types referenced by Views, with the exception of virtual types (containing #)
            [hashtable[]] $TypeNames =
                Get-ChildItem -Filter *.format.ps1xml -Path $ModulePath -Recurse -File |
                Select-Xml -XPath '//TypeName/text()' |
                ForEach-Object { $PSItem.Node.Value } |
                Sort-Object -Unique |
                Where-Object { $PSItem -notlike '*#*' } |
                ForEach-Object { @{ TypeName = $PSItem } }
        }

        It 'referenced type <TypeName> exists' -TestCases $TypeNames -Test {
            param([string] $TypeName)

            ($TypeName -as [Type]) | Should -Not -BeNull
        }
    }

    Context 'Assemblies' {
        BeforeDiscovery {
            # Only test .NET Framework assemblies
            [string] $frameworkDirectory = Join-Path -Path $ModulePath -ChildPath 'net480'
            [hashtable[]] $AllAssemblies =
                Get-ChildItem $frameworkDirectory -Recurse -Filter *.dll |
                ForEach-Object { @{ Assembly = $PSItem } }

            [hashtable[]] $OwnedAssemblies = $AllAssemblies | Where-Object { $PSItem.Assembly.Name -like 'DSInternals.*.dll' }
        }

        It '<Assembly> has a strong name' -TestCases $AllAssemblies -Test {
            param([System.IO.FileInfo] $Assembly)

            if ($Assembly.DirectoryName -like '*Debug*') {
                # Only do this check for Release builds, not Debug ones
                Set-ItResult -Skip -Because 'this is a Debug build.'
            } else {
                [System.Reflection.AssemblyName] $assemblyName = [System.Reflection.AssemblyName]::GetAssemblyName($Assembly.FullName)
                $assemblyName.Flags.HasFlag([System.Reflection.AssemblyNameFlags]::PublicKey) | Should -Be $true
            }
        }

        It '<Assembly> has file details' -TestCases $OwnedAssemblies -Test {
            param([System.IO.FileInfo] $Assembly)

            $Assembly.VersionInfo.ProductName | Should -Not -BeNullOrEmpty
        }

        It '<Assembly> has up-to-date copyright information' -TestCases $ownedAssemblies -Test {
            param([System.IO.FileInfo] $Assembly)

            [string] $expectedCopyrightInfo = '*2024-{0}*' -f (Get-Date).Year
            $Assembly.VersionInfo.LegalCopyright | Should -BeLike $expectedCopyrightInfo
        }
    }
}
