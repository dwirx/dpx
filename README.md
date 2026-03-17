# DPX

`dpx` is a Go CLI and TUI tool for encrypting `.env` and similar local secret files into `.dpx` envelopes.

It supports two practical encryption modes:
- `age` for public-key workflows and team sharing
- `Argon2id + XChaCha20-Poly1305` for password-based encryption

## ✨ Features

- Encrypt `.env` into `.env.dpx`
- Decrypt back to the original filename by default
- Guided CLI and interactive TUI modes
- Smart file suggestions for `.env`, `.env.*`, `*.env`, `.secret*`, `.credentials*`
- Inline `.env` key encryption: `API_KEY=ENC[age:...]` / `ENC[pwd:v1:...]`
- Password confirmation on encrypt flows (CLI + TUI) to reduce typo risk
- Safe `uninstall` command with confirmation and cleanup flags
- `doctor` command to check config, key, and project readiness
- Hidden password prompt on real terminals
- Armored `.dpx` file format with metadata tamper detection
- GitHub Actions CI and manual release workflow
- Quick install scripts for Linux, macOS, and Windows

## 🚀 Quick Install

Recommended install from GitHub Releases.

### Linux and macOS

```bash
curl -sSL https://github.com/dwirx/dpx/releases/latest/download/install.sh | bash
```

### Windows PowerShell

```powershell
irm https://github.com/dwirx/dpx/releases/latest/download/install.ps1 | iex
```

After install:

```bash
dpx --version
```

## 📦 Download Binary

Download from GitHub Releases:

| Platform | Architecture | Download |
| --- | --- | --- |
| Linux | x64 | `dpx_linux_amd64.tar.gz` |
| Linux | ARM64 | `dpx_linux_arm64.tar.gz` |
| macOS | Intel | `dpx_darwin_amd64.tar.gz` |
| macOS | Apple Silicon | `dpx_darwin_arm64.tar.gz` |
| Windows | x64 | `dpx_windows_amd64.zip` |
| Windows | ARM64 | `dpx_windows_arm64.zip` |

### Manual Install

Linux and macOS:

```bash
tar -xzf dpx_*.tar.gz
sudo mv dpx /usr/local/bin/
dpx --version
```

Windows:
- Extract the `.zip`
- Move `dpx.exe` to a folder in your `PATH`
- Run `dpx --version`

## 🧰 Install via Go

```bash
go install github.com/dwirx/dpx/cmd/dpx@latest
```

## 🛠️ Build From Source

```bash
git clone https://github.com/dwirx/dpx
cd dpx
go build -o dpx ./cmd/dpx
sudo mv dpx /usr/local/bin/  # Linux/macOS
```

## ⚡ Quick Start

### 1. Initialize a project

```bash
dpx init
```

Expected output:

```text
✅ Created .dpx.yaml

Next steps:
  1. Run 'dpx keygen' to generate a key pair
  2. Add your public key to .dpx.yaml
  3. Run 'dpx encrypt <file>' to encrypt your secrets
```

### 2. Generate an `age` key pair

```bash
dpx keygen
```

Example output:

```text
╔══════════════════════════════════════════════════════════════════╗
║                  🔑 DPX Key Generated Successfully               ║
╠══════════════════════════════════════════════════════════════════╣
║ Backend: age                                                     ║
║ Key file: ~/.config/dpx/age-keys.txt                            ║
╠══════════════════════════════════════════════════════════════════╣
║ Public Key (add to .dpx.yaml):                                   ║
║   age1...                                                        ║
╚══════════════════════════════════════════════════════════════════╝
```

### 3. Encrypt with a password

```bash
dpx encrypt .env --password 'super-secret-password'
```

Output:

```text
Encrypted .env -> .env.dpx
```

### 4. Decrypt back

```bash
dpx decrypt .env.dpx --password 'super-secret-password'
```

Output:

```text
Decrypted .env.dpx -> .env
```

### 5. Use interactive CLI (guided)

```bash
dpx encrypt
```

Typical guided flow:
- pick a file from suggestions or manual path
- choose mode (`age` or `password`)
- if password mode, type password + confirm password
- confirm output path

### 6. Use the TUI

```bash
dpx tui
```

The TUI can:
- choose `Encrypt`, `Decrypt`, or `Inspect`
- suggest likely secret files
- choose `Password` or `Age`
- prompt for recipients or password (+ confirmation when encrypting)
- confirm output path

## 🧭 Common Usage

### Encrypt with a password

Prompt for password interactively:

```bash
dpx encrypt .env
```

DPX will ask:
- `Password:`
- `Confirm password:`

Pass the password explicitly:

```bash
dpx encrypt .env --password 'secret'
```

Write to a custom output:

```bash
dpx encrypt .env --password 'secret' --out configs/prod.env.dpx
```

### Encrypt with `age`

Use recipients from `.dpx.yaml`:

```bash
dpx encrypt .env --age
```

Pass recipients directly:

```bash
dpx encrypt .env --age --recipient age1abc...,age1def...
```

### Decrypt a file

Password mode with prompt:

```bash
dpx decrypt .env.dpx
```

Password mode with explicit password:

```bash
dpx decrypt .env.dpx --password 'secret'
```

`age` mode with explicit identity file:

```bash
dpx decrypt .env.dpx --identity ~/.config/dpx/age-keys.txt
```

Restore to a different path:

```bash
dpx decrypt .env.dpx --out .env.restored
```

### Inline `.env` key encryption

Encrypt selected keys only (values become `ENC[...]` inline):

```bash
dpx env encrypt .env --mode password --keys API_KEY,JWT_SECRET
```

Decrypt inline encrypted keys:

```bash
dpx env decrypt .env.dpx
```

Interactive inline flow:

```bash
dpx env encrypt
```

DPX can prompt for:
- `.env` file selection
- mode (`age` or `password`)
- key selection (`all` or specific indexes)
- password + confirm password (for password mode)

### Inspect metadata safely

```bash
dpx inspect .env.dpx
```

Example output:

```text
Version: 1
Mode: password
Original Name: .env
Created At: 2026-03-17 10:11:12+00:00
KDF: argon2id
```

### Check project readiness

```bash
dpx doctor
```

`doctor` reports:
- which config file is in use
- whether a legacy config is being used
- whether the key file exists
- number of configured recipients
- number of suggested files
- number of `.dpx` files in the current directory

### Uninstall and cleanup

Preview in help:

```bash
dpx --help
```

Remove project config only (asks confirmation):

```bash
dpx uninstall
```

Full cleanup without prompt:

```bash
dpx uninstall --yes --remove-key --remove-encrypted
```

## 📚 CLI Reference

### `dpx init`

Create `.dpx.yaml` in the current directory.

Behavior:
- fails if `.dpx.yaml` already exists
- also fails if legacy `.dopx.yaml` already exists

### `dpx keygen [--out <path>]`

Generate an `age` identity file.

Default key path:

```text
~/.config/dpx/age-keys.txt
```

### `dpx uninstall [--yes] [--remove-key] [--remove-encrypted]`

Remove DPX files safely.

Behavior:
- removes `.dpx.yaml`/`.dopx.yaml` in current directory
- `--remove-key` removes key file only if it is in a safe scope (default/legacy path or inside current project)
- `--remove-encrypted` removes `.dpx` files in current directory
- without `--yes`, command asks for explicit confirmation (`YES`)

### `dpx encrypt <file> [--password <text>] [--age] [--recipient <csv>] [--out <path>]`

Encrypt a file into `.dpx`.

Rules:
- `--password` selects password mode
- `--age` selects `age` mode
- if no output is provided, output becomes `<file>.dpx`
- if no file is provided, DPX starts guided picker/search flow
- if password is prompted interactively, DPX asks password confirmation

### `dpx decrypt <file.dpx> [--password <text>] [--identity <path>] [--out <path>]`

Decrypt a `.dpx` file.

Rules:
- DPX auto-detects password or `age` mode from metadata
- if no output is provided, DPX restores the original filename from metadata
- if password mode is detected and no password is provided, DPX prompts for it

### `dpx env encrypt [<file>] [--mode age|password] [--keys <csv>] [--recipient <csv>] [--password <text>] [--out <path>]`

Encrypt selected `.env` keys inline into `ENC[...]` values.

Rules:
- when `<file>` is omitted, DPX suggests `.env` candidates
- when `--keys` is omitted, DPX asks interactive key selection
- in interactive password mode, DPX asks password confirmation

### `dpx env decrypt [<file.dpx>] [--password <text>] [--identity <path>] [--out <path>]`

Decrypt inline encrypted `ENC[...]` values back into plaintext env values.

### `dpx inspect <file.dpx>`

Show safe metadata only.

### `dpx doctor`

Show project and local environment readiness.

### `dpx tui`

Launch the interactive interface.

### `dpx version`
### `dpx --version`
### `dpx -v`

Print the current version.

## Config File

Primary config file:

```text
.dpx.yaml
```

Legacy config still supported:

```text
.dopx.yaml
```

Example:

```yaml
version: 1
default_suffix: ".dpx"
key_file: "~/.config/dpx/age-keys.txt"
age:
  recipients:
    - age1examplepublickey
discovery:
  include:
    - ".env"
    - ".env.*"
    - "*.env"
    - ".secret*"
    - ".credentials*"
```

## File Format

DPX writes armored text envelopes.

Current header prefix:

```text
DPX-File-Version: 1
```

Legacy envelopes are still accepted:

```text
DOPX-File-Version: 1
```

Default encrypted output:

```text
.env.dpx
```

## Security Notes

- Password mode uses `Argon2id`
- Password encryption uses `XChaCha20-Poly1305`
- Key mode uses `filippo.io/age`
- Outer `.dpx` metadata is checked against protected inner metadata
- Tampered metadata causes decryption to fail
- Decryption restores original bytes
- Password prompts are hidden on real terminals
- Keep private keys outside the repository

## GitHub Actions

This repository includes:
- CI workflow: `.github/workflows/ci.yml`
- Manual release workflow: `.github/workflows/release.yml`

### CI workflow

Runs on:
- push to `main`
- pull requests

Checks:
- `go test ./...`
- binary build
- release asset build
- Linux installer smoke test against locally served release assets

### Manual release workflow

The release workflow is triggered manually from GitHub Actions with a version input.

Example version input:

```text
v0.2.0
```

What the workflow does:
- validates the version string
- checks that the tag does not already exist
- runs tests
- builds release assets
- smoke tests `install.sh`
- creates and pushes the tag
- publishes a GitHub Release

## Release Assets

The release workflow publishes stable asset names:

- `dpx_linux_amd64.tar.gz`
- `dpx_linux_arm64.tar.gz`
- `dpx_darwin_amd64.tar.gz`
- `dpx_darwin_arm64.tar.gz`
- `dpx_windows_amd64.zip`
- `dpx_windows_arm64.zip`
- `install.sh`
- `install.ps1`
- `checksums.txt`

## Development

Run tests:

```bash
make test
```

Build:

```bash
make build VERSION=dev
```

Build local release assets:

```bash
make release VERSION=v0.2.0
```

Artifacts are written to `dist/`.

## Migration From `dopx`

DPX is the new primary name.

Compatibility retained:
- `.dpx.yaml` is preferred
- `.dopx.yaml` is still read
- `~/.config/dpx/age-keys.txt` is preferred
- `~/.config/dopx/age-keys.txt` is still used as fallback
- envelopes using `DOPX-File-Version` still decrypt

## Troubleshooting

### `config already exists`

You already have `.dpx.yaml` or `.dopx.yaml` in the working directory.

### `no candidate files found`

DPX did not find a file matching its discovery patterns in the current directory.

### Password decryption fails

Possible causes:
- wrong password
- tampered file
- corrupted payload

### `age` decryption fails

Possible causes:
- wrong identity file
- wrong recipient
- missing private key file

## Repository Hygiene

Do not commit:
- plaintext `.env` files with real secrets
- generated `.dpx` secret files
- private keys
- local binaries
- local `dist/` artifacts
