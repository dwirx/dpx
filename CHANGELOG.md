# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
