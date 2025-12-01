<#
.SYNOPSIS
Refreshes MD documentation files for the C# project.

.DESCRIPTION
Requires docfx to be installed and available in PATH.
#>

#Requires -Version 5

[string] $parentDir = Split-Path -Path $PSScriptRoot -Parent -ErrorAction Stop

# Generate the markdown files for the .NET project
docfx metadata "$parentDir/docfx.json"

# Remove the unnecessary TOC file if it exists
Remove-Item -Path "$parentDir/Documentation/DotNet/toc.yml" -ErrorAction SilentlyContinue

# Rename the index file to README.md
Remove-Item -Path "$parentDir/Documentation/DotNet/README.md" -ErrorAction SilentlyContinue
Rename-Item -Path "$parentDir/Documentation/DotNet/DSInternals.Win32.RpcFilters.md" -NewName "README.md" -ErrorAction SilentlyContinue
