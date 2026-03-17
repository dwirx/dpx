# Repository Guidelines

## Project Structure & Module Organization
`dpx` is a Go CLI/TUI project. Main entrypoint is `cmd/dpx/main.go`. Core logic is under `internal/`:
- `internal/app`: high-level service orchestration
- `internal/config`: `.dpx.yaml` parsing/defaults
- `internal/envelope`: `.dpx` file format and metadata
- `internal/crypto/*`: encryption backends (`age`, password)
- `internal/discovery`: candidate secret file detection
- `internal/tui`: interactive terminal flows

Release/install automation lives in `scripts/`. CI/CD workflows are in `.github/workflows/`.

## Build, Test, and Development Commands
- `make build VERSION=dev`: build local binary (`./dpx`) with version metadata.
- `make test`: run full test suite (`go test ./...`).
- `go test ./...`: direct test command used by CI.
- `make release VERSION=v0.2.0`: build cross-platform archives into `dist/`.
- `go build -o dpx ./cmd/dpx`: quick local build without release flags.

Use `make clean` to remove local binary and `dist/` artifacts.

## Coding Style & Naming Conventions
Follow standard Go conventions:
- Run `gofmt` on all changed Go files before opening a PR.
- Keep package names short/lowercase (`config`, `envelope`, `tui`).
- Exported identifiers use `CamelCase`; unexported names use `camelCase`.
- Prefer descriptive command/flag names consistent with existing CLI patterns (for example `--import-file`, `--no-config-update`).

## Testing Guidelines
Tests use Go’s built-in `testing` package and live next to code as `*_test.go`.
- Name tests by behavior, e.g. `TestRunDoctorReportsHealthyProject`.
- Use `t.Parallel()` for isolated tests.
- Use `t.TempDir()` and synthetic inputs; never depend on real user secrets.
- Ensure `go test ./...` passes locally before pushing.

No explicit coverage threshold is enforced, but new features and bug fixes should include regression tests.

## Commit & Pull Request Guidelines
Recent history favors short, imperative subjects (`add ...`, `fix ...`) with occasional Conventional Commit prefixes (`feat:`). Keep commits focused and readable.

PRs should include:
- concise summary of behavior changes
- linked issue/context when available
- test evidence (command run and result)
- terminal output/screenshots for user-facing CLI/TUI changes

## Security & Configuration Tips
Do not commit plaintext `.env` files, private keys, generated `.dpx` secrets, local binaries, or `dist/` artifacts. Use dummy values in fixtures and docs.
