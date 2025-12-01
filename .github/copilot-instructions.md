# RPCFilterManager – AI Agent Instructions

These notes make AI agents productive quickly in this repo. Keep changes minimal, match repo patterns, and prefer Windows-specific correctness over abstraction.

## Big Picture
- Deliverables: a .NET interop library (`DSInternals.Win32.RpcFilters`) and a PowerShell module (`DSInternals.RpcFilters`).
- Purpose: manage Windows RPC filters via Windows Filtering Platform (WFP) in user mode.
- Architecture:
  - Interop layer uses explicit P/Invoke to `Fwpuclnt.dll` (see `Src/DSInternals.Win32.RpcFilters/NativeMethods.cs`) plus safe handle wrappers in `SafeHandles/` and value/struct shims in `Structs/`.
  - High-level API: `RpcFilterManager` opens an engine session and supports listing (`GetFilters`), creating (`AddFilter`), and deleting (`RemoveFilter`) RPC filters. Translation between FWPM_* and `RpcFilter` happens in `RpcFilterManager.CreateFilter` and `Structs/FWPM_FILTER_CONDITION0.cs`.
  - Well-known protocol and opnum mapping is centralized in `WellKnownProtocolTranslator*.cs` and enums `WellKnownProtocol`, `WellKnownOperation`.
  - PowerShell: thin wrapper cmdlets (`Get-/New-/Remove-RpcFilter`) implemented in C# under `Src/...PowerShell/Commands`, with a bootstrap script (`DSInternals.RpcFilters.Bootstrap.psm1`) selecting the right binary for PS 5.1 vs 7+.

## Build and Layout
- Run from repo root:
  - Build all (artifacts go to `Build/` via `Directory.Build.props`):
    ```cmd
    dotnet build --configuration Release
    ```
  - Library targets: `net48`, `net8.0-windows`. PowerShell targets the same TFMs.
- Strong-name signing only in Release if `Keys/DSInternals.Private.snk` exists. CI (`GITHUB_ACTIONS`) disables `GeneratePackageOnBuild` to allow signing first.
- PowerShell module output after Release build: `Build/bin/DSInternals.Win32.RpcFilters.PowerShell/Release/DSInternals.RpcFilters/` (contains `net48` and `net8.0-windows` subfolders plus `.psd1/.psm1/.ps1xml`).

## Tests
- .NET tests (MSTest): `Src/DSInternals.Win32.RpcFilters.Tests`
  - Many tests interact with WFP and require Windows; filter-add/remove tests typically require elevation and a predictable environment.
  - Run selectively and elevated when modifying interop:
    ```cmd
    dotnet test --output Detailed --configuration Release -- --results-directory "Build/TestResults"
    ```
- PowerShell tests (Pester 5): `Src/DSInternals.Win32.RpcFilters.PowerShell/Tests`
  - Build Release first; then:
    ```cmd
    powershell.exe -ExecutionPolicy Bypass -NonInteractive -NoLogo -NoProfile -File "Src/DSInternals.Win32.RpcFilters.PowerShell/Test.ps1"
    ```
  - `Cmdlet.Tests.ps1` is marked `#Requires -RunAsAdministrator` and imports the built module via the `Build/bin/DSInternals.Win32.RpcFilters.PowerShell/Release/DSInternals.RpcFilters` path.
  - Ignore any failed tests stemming from insufficient permissions and do not try to fix them.

## Conventions and Patterns
- Interop:
  - Keep P/Invoke declarations in `NativeMethods.cs`. Use safe handles from `SafeHandles/` and free unmanaged memory via `FwpmFreeMemory0` where wrappers expose `SafeFwpmBuffer`.
  - Add new filter conditions through factory methods in `Structs/FWPM_FILTER_CONDITION0.cs`; mirror parsing in `RpcFilterManager.CreateFilter`.
  - Map Win32 errors to .NET exceptions via `RpcFilterManager.ValidateResult`; extend this switch when adding new calls.
- Public API:
  - `RpcFilter` is the DTO. Defaults: `Name='RPCFilter'`, `Description='RPC Filter'`. Weight currently supports relative range 0–15 only.
  - OS feature gates exposed as `RpcFilterManager.IsOpnumFilterSupported`, `IsIpAddressFilterWithNamedPipesSupported`, `IsAuditParametersSupported` — PowerShell surfaces these as warnings, not hard errors.
- PowerShell:
  - Parameters follow aliases shown in `NewRpcFilterCommand` (e.g., `-AuthLevel`, `-ProtSeq`, `-SDDL`). Keep validation aligned with interop limitations (e.g., `-NamedPipe` must match `^\\PIPE\\.+`).
  - Bootstrap module imports the correct TFM DLL; do not put binary loads into `.psd1`.

## Windows/WFP Behaviors to Respect
- Named pipes are case-sensitive; comparisons use `FWP_MATCH_EQUAL` on blob data – no case-insensitive operator available.
- Subnet matching is not effective; IP subnet conditions are ignored by WFP for RPC scenarios. Emit warnings rather than enforcing.
- OpNum filtering requires Windows 11 24H2/Server 2025+. IP conditions with named pipes require 25H2+. Parameter buffer auditing also 25H2+.

## Docs and Packaging
- .NET API docs (Markdown) generated via docfx metadata:
  ```powershell
  Scripts/Update-DotNetDocumentation.ps1
  ```
- PowerShell help uses platyPS; build module (Release) first, then:
  ```powershell
  Scripts/Update-PowerShellDocumentation.ps1
  ```
- NuGet packing for the library happens on Release; CI disables auto-pack until signing is done.

## When Adding Features
- Extend `FWPM_FILTER_CONDITION0` and `RpcFilterManager.CreateFilter` together; expose new fields in `RpcFilter` and wire PowerShell parameters with validation and warnings consistent with OS gates.
- Update translators (`WellKnownProtocolTranslator*.cs`) and corresponding Pester tests if adding protocols/operations.
- Keep artifacts under `Build/`; do not revert `bin/obj` to per-project defaults.
