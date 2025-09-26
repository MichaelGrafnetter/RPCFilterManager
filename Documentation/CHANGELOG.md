# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [1.1] - 2025-09-26

### Added

- The `-AuthenticationLevelMatchType` parameter of the `New-RpcFilter` cmdlet can now be used to audit or enforce packet encryption in a more straightforward way.
- The `-SecurityDescriptorNegativeMatch` parameter of the `New-RpcFilter` cmdlet simplifies auditing or blocking traffic based on group membership.

### Fixed

- The `Get-RpcFilterEvent` cmdlet now correctly bypasses firewall on localhost.

## [1.0] - 2025-09-26

- Initial release

[Unreleased]: https://github.com/MichaelGrafnetter/RPCFilterManager/compare/v1.1...HEAD
[1.1]: https://github.com/MichaelGrafnetter/RPCFilterManager/compare/v1.0...1.1
[1.0]: https://github.com/MichaelGrafnetter/RPCFilterManager/releases/tag/v1.0
