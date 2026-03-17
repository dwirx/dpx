# Repository Guidelines

## Project Structure & Module Organization
`dpx` is a Go CLI/TUI project. Entry point: `cmd/dpx/main.go`.

Core packages in `internal/`:
- `app`: high-level encrypt/decrypt services.
- `config`: `.dpx.yaml` loading/defaults.
- `envelope`: armored `.dpx` metadata/payload format.
- `crypto/agex` and `crypto/password`: encryption backends.
- `envcrypt`: inline `.env` token encryption (`ENC[...]`).
- `discovery`: suggested file scanning.
- `tui`: fullscreen and fallback interactive flows.

Automation:
- `scripts/`: release/install scripts.
- `.github/workflows/`: CI and manual release workflows.

## Build, Test, and Development Commands
- `make build VERSION=dev`: build local binary with version metadata.
- `make test` or `go test ./...`: run all tests.
- `go test -race ./cmd/dpx ./internal/tui`: race check for user-facing flows.
- `make release VERSION=vX.Y.Z`: build cross-platform assets in `dist/`.
- `go build -o dpx ./cmd/dpx`: quick local binary build.
- `dpx --help`: verify CLI UX/help output after command changes.

## Coding Style & Naming Conventions
Follow standard Go conventions:
- Run `gofmt` on changed `.go` files before commit.
- Keep package names short and lowercase.
- Use `CamelCase` for exported symbols, `camelCase` for internal helpers.
- Keep CLI flags explicit and consistent (example: `--identity`, `--password`, `--out`).
- Match existing prompt wording for interactive CLI/TUI behavior.

## Testing Guidelines
Tests use Go’s built-in `testing` package (`*_test.go` beside source files).
- Name tests by behavior (example: `TestRunEnvInlinePasswordEncryptDecrypt`).
- Use `t.TempDir()` and fake secrets only.
- Prefer table tests for file/mode combinations (`.txt`, `.md`, `.bin`, `.exe`, `.env`).
- For feature changes, add regression tests in service + CLI/TUI layers when relevant.
- Ensure `go test ./...` passes before push.

## Commit & Pull Request Guidelines
Use focused, readable commits. Conventional prefixes are preferred (`feat:`, `fix:`, `docs:`).

PRs should include:
- concise behavior summary
- issue/context link (if available)
- test evidence (`go test ./...`, race checks when relevant)
- terminal snippets or screenshots for CLI/TUI UX updates

## Security & Configuration Tips
Never commit plaintext real secrets, private keys, generated secret `.dpx` files, or local build artifacts.

Use dummy fixtures in tests/docs and prefer `.env` samples with non-production placeholder values.
