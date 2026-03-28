# RPCFilterManager – AI Agent Instructions

## Agent Workflow and Scope

- Prefer project tasks for build when available (for example, workspace task `build`); otherwise use the documented `dotnet` commands.
- Do not modify generated outputs or artifacts unless the task explicitly asks for it:
  - `Build/`
  - `Documentation/DotNet/*` and `Documentation/PowerShell/*` (regenerate via scripts instead of hand-editing)
- Keep API and cmdlet behavior backward compatible unless a breaking change is explicitly requested.
- Never commit, tag, or create branches unless explicitly requested.

## Overview

- Deliverables:
  - .NET interop library: `DSInternals.Win32.RpcFilters`
  - PowerShell module: `DSInternals.RpcFilters`
- Purpose: Manage Windows RPC filters through Windows Filtering Platform (WFP) in user mode.
- Core architecture:
  - Interop layer: Explicit P/Invoke to `Fwpuclnt.dll` in `Src/DSInternals.Win32.RpcFilters/NativeMethods.cs`, plus safe handles in `SafeHandles/` and native struct shims in `Structs/`.
  - High-level API: `RpcFilterManager` manages engine sessions and supports filter listing (`GetFilters`), creation (`AddFilter`), and deletion (`RemoveFilter`). Translation between FWPM_* structures and `RpcFilter` is implemented in `RpcFilterManager.CreateFilter` and `Structs/FWPM_FILTER_CONDITION0.cs`.
  - Well-known protocol and opnum mapping: `WellKnownProtocolTranslator*.cs` with enums `WellKnownProtocol` and `WellKnownOperation`.
  - PowerShell surface: Thin C# cmdlets (`Get-/New-/Remove-RpcFilter`) under `Src/...PowerShell/Commands` plus auditing helpers in `DSInternals.RpcFilters.Auditing.psm1`.

## Build and Output Layout

- Run from the repository root.
- Main solution file: `RpcFilterManager.slnx`.
- Build all projects (artifacts are redirected to `Build/` by `Src/Directory.Build.props`):

  ```cmd
  dotnet build RpcFilterManager.slnx --configuration Release
  ```

- Target frameworks:
  - Library: `net48`, `net8.0-windows`
  - PowerShell project: same TFMs
  - Test project: `net48`, `net10.0-windows`
- PowerShell module output after Release build:
  `Build/bin/DSInternals.Win32.RpcFilters.PowerShell/Release/DSInternals.RpcFilters/`
  (contains `net48` and `net8.0-windows` subfolders plus shared module files such as `.psd1`, `.psm1`, `.ps1xml`).

## Test Guidance

- .NET tests (MSTest): `Src/DSInternals.Win32.RpcFilters.Tests`
  - Many tests interact with WFP and require Windows.
  - Filter add/remove scenarios typically require elevation and a predictable environment.
  - When changing interop code, run selectively and elevated:

    ```cmd
    dotnet test Src/DSInternals.Win32.RpcFilters.Tests/DSInternals.Win32.RpcFilters.Tests.csproj --configuration Release --logger "console;verbosity=detailed" --results-directory "Build/TestResults"
    ```

- PowerShell tests (Pester 5): `Src/DSInternals.Win32.RpcFilters.PowerShell/Tests`
  - Build Release first, then run:

    ```cmd
    powershell.exe -ExecutionPolicy Bypass -NonInteractive -NoLogo -NoProfile -File "Src/DSInternals.Win32.RpcFilters.PowerShell/Test.ps1" -Configuration Release
    ```

  - `Cmdlet.Tests.ps1` uses `#Requires -RunAsAdministrator` and imports from:
    `Build/bin/DSInternals.Win32.RpcFilters.PowerShell/Release/DSInternals.RpcFilters`
  - Ignore test failures caused only by insufficient permissions; do not attempt to “fix” those failures.

## Coding Conventions

- Interop layer:
  - Keep P/Invoke declarations in `NativeMethods.cs`.
  - Use safe handles from `SafeHandles/`.
  - Free unmanaged memory via `FwpmFreeMemory0` where wrappers expose `SafeFwpmBuffer`.
  - When adding filter conditions, update both:
    - factory methods in `Structs/FWPM_FILTER_CONDITION0.cs`
    - reverse parsing in `RpcFilterManager.CreateFilter`
  - Convert Win32 errors through `RpcFilterManager.ValidateResult`; extend its mapping when adding new native calls.

- Public API:
  - `RpcFilter` is the DTO.
  - Feature gates are exposed by:
    - `RpcFilterManager.IsOpnumFilterSupported`
    - `RpcFilterManager.IsIpAddressFilterWithNamedPipesSupported`
    - `RpcFilterManager.IsAuditParametersSupported`
  - In PowerShell, surface unsupported-feature conditions as warnings, not hard errors.

## Documentation

- Generate .NET API Markdown docs (docfx metadata):

  ```powershell
  Scripts/Update-DotNetDocumentation.ps1
  ```

- Generate PowerShell help (platyPS); build the Release module first:

  ```powershell
  Scripts/Update-PowerShellDocumentation.ps1
  ```

## Packaging

- NuGet package creation for the library only happens on Release builds.
