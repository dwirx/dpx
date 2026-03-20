# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.0.15] - 2026-03-20

### Added
- `dpx rotate`: New command to seamlessly regenerate age key pairs and re-encrypt all `.dpx` files and inline secrets.
- `dpx hook install`/`uninstall`: New command to manage a Git pre-commit hook that prevents accidental commits of plaintext secrets using `dpx policy check`.
- TUI integration for `Regenerate Key`, `Git Hook Install`, and `Git Hook Uninstall` with elegant sub-handlers to safely execute terminal-heavy operations.
- Expanded `README` documentation for key rotation and git pre-commit hooks.

### Changed
- Strengthened the interactive warning prompt for destructive key rotation operations.

## [v0.0.14] - 2026-03-19

### Fixed
- Fullscreen TUI no longer exits when typing/pasting `q` inside input fields.
- Windows import-key paste flow is now stable for age key blocks containing `q` in the public key line.
- Added regression test to ensure `q` is treated as text input (not global quit) during key import input stages.

## [v0.0.13] - 2026-03-19

### Added
- `dpx update` now emits progress events and renders a terminal download progress bar while fetching release assets.

### Changed
- Windows can now run fullscreen Bubble Tea TUI when terminal is interactive (TTY), matching Linux/macOS experience.
- Added `DPX_TUI_MODE` override:
  - `fallback`/`plain` forces text fallback TUI
  - `fullscreen`/`bubble` keeps fullscreen TUI when TTY is available

### Fixed
- Fullscreen TUI import flow now handles key-block paste better:
  - detects accidental key-block paste in `From file` input
  - supports line-by-line key-block paste with `Ctrl+D` finalize
- Improved TUI navigation ergonomics with additional keys (`Tab`, `Shift+Tab`, `Ctrl+N`, `Ctrl+P`, `Home/End`, `Ctrl+B` back).

## [v0.0.12] - 2026-03-19

### Changed
- `dpx tui` now forces fallback TUI on Windows to avoid multiline key-paste instability in fullscreen mode.

### Fixed
- Import key flow in fallback TUI now tolerates accidental paste at the `From file` prompt:
  - if input looks like key-block content (`# ...` metadata or `AGE-SECRET-KEY-...`), it is parsed as key content instead of a filesystem path
  - multiline key block can continue immediately and is merged safely before import
- Added regression coverage for Windows fallback selection and pasted key-block import handling.

## [v0.0.11] - 2026-03-18

### Added
- `keygen` help/docs now document key import workflow:
  - `--import-file`
  - `--import-stdin`
  - `.dpx.yaml` auto-sync behavior
- New self-update commands:
  - `dpx update`
  - `dpx update --version vX.Y.Z`
  - `dpx rollback`
- Cross-platform update asset resolution for Linux/macOS/Windows with rollback backup support.

### Changed
- `dpx keygen --import-file <age-keys.txt>` now uses the import file path as default output when `--out` is omitted.
- TUI import flow now pre-fills the output key path with the selected import file path.

### Fixed
- TUI key import now handles pasted `age-keys.txt` blocks more safely:
  - waits for `AGE-SECRET-KEY-...` in Bubble Tea input before proceeding
  - fallback TUI auto-stops pasted block at the private-key line (no mandatory `END`)
  - clearer validation when no private key line is found
- Import parser now tolerates noisy shell paste artifacts and extracts the first valid `AGE-SECRET-KEY-...` token.

## [v0.0.9] - 2026-03-18

### Added
- Password envelope metadata now includes:
  - `Encryption-Algorithm`
  - `Encryption-Nonce`
- Password KDF profiles for brute-force resistance:
  - `balanced` (default CLI)
  - `hardened`
  - `paranoid`
- New CLI flags for password flows:
  - `dpx encrypt --kdf-profile ...`
  - `dpx env encrypt --kdf-profile ...`
  - `dpx env set --kdf-profile ...`
- TUI/fallback password encryption defaults to `hardened` KDF profile.

### Changed
- Password envelope encryption now binds metadata to ciphertext integrity using authenticated AAD.
- `dpx decrypt` now auto-detects inline `.env.dpx` (`ENC[...]`) and routes to inline decrypt flow.
- CLI help and docs updated for KDF profiles and strengthened security defaults.

### Fixed
- Improved decrypt UX for plaintext/non-envelope files with clearer error:
  - not a DPX envelope and no inline ENC tokens found.
- Maintained backward compatibility for legacy password envelope format (nonce-prefixed payload).

## [v0.0.8] - 2026-03-18

### Added
- `dpx run` command to load env values from `.env`, `.env.dpx`, or inline encrypted `.env.dpx` and inject them into a child process.
- `dpx policy check` command to detect plaintext sensitive keys in env/json/yaml-like files.
- `dpx env list` and `dpx env get` for reading env keys from plaintext/encrypted sources.
- `dpx env set` to add/update env keys with optional inline encryption.
- `dpx env updatekeys` to rotate recipients for inline `ENC[age:...]` values.
- `policy.creation_rules` support in `.dpx.yaml` for default mode and key selection per file pattern.
- New docs:
  - `docs/env-inline-workflow.md`
  - `docs/creation-rules.md`
  - `docs/testing-report-2026-03-18.md`

### Changed
- Expanded CLI help text and README examples for new env/runtime/policy commands.
- Added broader automated coverage for env inline workflows, recipient rotation, policy checks, and runtime injection.

## [v0.0.7] - 2026-03-17

### Added
- Inline `.env` token encryption/decryption support with:
  - `ENC[age:...]`
  - `ENC[pwd:v1:...]`
- `dpx env encrypt` and `dpx env decrypt` workflows for inline `.env` values.
- Interactive key selection for env-inline encryption.
- Password confirmation prompts on encrypt flows (CLI and TUI env-inline).
- Automated tests for env-inline service, CLI, and TUI round-trip flows.

### Changed
- Improved interactive CLI help output with guided usage examples.
- Expanded README to document interactive flow and env-inline commands.

## [v0.0.6] - 2026-03-17

See release notes: <https://github.com/dwirx/dpx/releases/tag/v0.0.6>

## [v0.0.5] - 2026-03-17

See release notes: <https://github.com/dwirx/dpx/releases/tag/v0.0.5>

## [v0.0.4] - 2026-03-17

See release notes: <https://github.com/dwirx/dpx/releases/tag/v0.0.4>

## [v0.0.3] - 2026-03-17

See release notes: <https://github.com/dwirx/dpx/releases/tag/v0.0.3>

## [v0.0.2] - 2026-03-17

See release notes: <https://github.com/dwirx/dpx/releases/tag/v0.0.2>

## [v0.0.1] - 2026-03-17

See release notes: <https://github.com/dwirx/dpx/releases/tag/v0.0.1>
