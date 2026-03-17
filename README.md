# DPX

`dpx` is a Go CLI and TUI tool for encrypting `.env` and other local secret files into `.dpx` envelopes.

It is designed for two practical workflows:
- password-based encryption for quick local or one-to-one sharing
- `age`-based encryption for repeatable team and key-based workflows

## Why DPX

DPX focuses on a narrow use case and keeps the workflow simple:
- encrypt `.env` and similar files into `.dpx`
- decrypt back to the original filename by default
- use a guided TUI when you do not want to remember flags
- inspect metadata safely without exposing plaintext
- check project readiness with `dpx doctor`

## Security Model

DPX supports two encryption modes:

### Password mode
- KDF: `Argon2id`
- Cipher: `XChaCha20-Poly1305`
- Use this when you want a strong password-based workflow

### Key mode
- Backend: `age`
- Use this when you want public-key encryption and shared team workflows

### Metadata protection
- outer `.dpx` metadata is validated against protected inner metadata
- tampering with the stored filename, mode, or other protected fields causes decryption to fail

## Features

- CLI and TUI interfaces
- `init`, `keygen`, `encrypt`, `decrypt`, `inspect`, `doctor`, `tui`, `version`
- smart file suggestions for `.env`, `.env.*`, `*.env`, `.secret*`, `.credentials*`
- hidden password prompt on real terminals
- `.dpx.yaml` as the primary config file
- legacy compatibility for `.dopx.yaml`
- legacy compatibility for older `DOPX-File-Version` envelopes
- legacy key fallback from `~/.config/dopx/age-keys.txt`

## Install

### Build locally

```bash
go build -o dpx ./cmd/dpx
```

### Build with Make

```bash
make build
```

### Run tests

```bash
go test ./...
```

## Quick Start

### 1. Initialize a project

```bash
./dpx init
```

Example output:

```text
✅ Created .dpx.yaml

Next steps:
  1. Run 'dpx keygen' to generate a key pair
  2. Add your public key to .dpx.yaml
  3. Run 'dpx encrypt <file>' to encrypt your secrets
```

### 2. Generate an `age` key

```bash
./dpx keygen
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

### 3. Encrypt a file with a password

```bash
./dpx encrypt .env --password 'super-secret-password'
```

Output:

```text
Encrypted .env -> .env.dpx
```

### 4. Decrypt it back

```bash
./dpx decrypt .env.dpx --password 'super-secret-password'
```

Output:

```text
Decrypted .env.dpx -> .env
```

### 5. Use the TUI

```bash
./dpx tui
```

The TUI can:
- suggest candidate secret files
- let you choose password or `age`
- prompt for recipients or password
- confirm output paths
- inspect `.dpx` files

## Common Workflows

### Encrypt with a password

Interactive prompt:

```bash
./dpx encrypt .env
```

Non-interactive:

```bash
./dpx encrypt .env --password 'secret'
```

Custom output path:

```bash
./dpx encrypt .env --password 'secret' --out secrets/prod.env.dpx
```

### Encrypt with `age`

Using recipients from `.dpx.yaml`:

```bash
./dpx encrypt .env --age
```

Using explicit recipients:

```bash
./dpx encrypt .env --age --recipient age1abc...,age1def...
```

### Decrypt a password-protected file

Prompt for password:

```bash
./dpx decrypt .env.dpx
```

Pass password explicitly:

```bash
./dpx decrypt .env.dpx --password 'secret'
```

Write to a different output path:

```bash
./dpx decrypt .env.dpx --password 'secret' --out .env.restored
```

### Decrypt an `age`-encrypted file

Using the default key file:

```bash
./dpx decrypt .env.dpx
```

Using a specific identity file:

```bash
./dpx decrypt .env.dpx --identity ~/.config/dpx/age-keys.txt
```

### Inspect metadata safely

```bash
./dpx inspect .env.dpx
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
./dpx doctor
```

What `doctor` checks:
- whether `.dpx.yaml` exists
- whether legacy `.dopx.yaml` is being used
- whether the key file exists
- recipient count from config
- how many candidate secret files were found
- how many `.dpx` files exist in the current directory

## CLI Reference

### `dpx init`

Creates `.dpx.yaml` in the current directory.

Behavior:
- fails if `.dpx.yaml` already exists
- also fails if legacy `.dopx.yaml` already exists

### `dpx keygen [--out <path>]`

Generates an `age` identity file.

Default output path:

```text
~/.config/dpx/age-keys.txt
```

Example:

```bash
./dpx keygen --out ~/.config/dpx/age-keys.txt
```

### `dpx encrypt <file> [--password <text>] [--age] [--recipient <csv>] [--out <path>]`

Encrypts a file into `.dpx`.

Notes:
- if `--password` is provided, password mode is used
- if `--age` is provided, `age` mode is used
- if no file is provided, DPX tries to suggest one interactively
- if no output path is provided, DPX writes `<file>.dpx`

Examples:

```bash
./dpx encrypt .env --password 'secret'
./dpx encrypt .env --age
./dpx encrypt .env --age --recipient age1abc...,age1def...
./dpx encrypt .env --password 'secret' --out releases/prod.env.dpx
```

### `dpx decrypt <file.dpx> [--password <text>] [--identity <path>] [--out <path>]`

Decrypts a `.dpx` file.

Notes:
- DPX auto-detects whether the file uses password mode or `age`
- if no output path is provided, DPX restores the original filename from metadata
- if no password is provided for password mode, DPX prompts for it

Examples:

```bash
./dpx decrypt .env.dpx
./dpx decrypt .env.dpx --password 'secret'
./dpx decrypt .env.dpx --identity ~/.config/dpx/age-keys.txt
./dpx decrypt .env.dpx --out .env.restored
```

### `dpx inspect <file.dpx>`

Prints safe metadata only.

### `dpx doctor`

Prints local environment and project readiness information.

### `dpx tui`

Launches the interactive interface.

Notes:
- uses a full-screen TUI on real terminals
- falls back to a guided line-based interface when stdin/stdout are not TTYs

### `dpx version`
### `dpx --version`
### `dpx -v`

Print the current version.

## TUI Behavior

The TUI supports three actions:
- Encrypt
- Decrypt
- Inspect

In interactive terminals, DPX uses a full-screen Bubble Tea UI.

When running through pipes or non-interactive environments, DPX uses a guided fallback UI that still supports:
- file selection
- mode selection
- password input
- output path selection

## Config File

Primary config file:

```text
.dpx.yaml
```

Legacy config file still supported:

```text
.dopx.yaml
```

Example config:

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

DPX writes an armored text envelope with metadata and payload.

Current header key:

```text
DPX-File-Version: 1
```

DPX can still read legacy envelopes that use:

```text
DOPX-File-Version: 1
```

Default encrypted filename:

```text
.env.dpx
```

## Security Notes

- password mode uses `Argon2id`
- password encryption uses `XChaCha20-Poly1305`
- key mode uses `filippo.io/age`
- decrypted plaintext is restored exactly as bytes from the original file
- password prompts are hidden on real terminals
- `doctor` does not expose plaintext
- config may contain public recipients, not private keys
- the private key file should stay outside the repository

## Migration Notes

DPX is the new primary name.

Compatibility retained:
- `.dpx.yaml` is preferred
- `.dopx.yaml` is still read
- `~/.config/dpx/age-keys.txt` is preferred
- `~/.config/dopx/age-keys.txt` is still used as fallback
- old envelopes using `DOPX-File-Version` still decrypt

## Development

Run tests:

```bash
make test
```

Build local binary:

```bash
make build VERSION=dev
```

Build release archives:

```bash
make release VERSION=v0.2.0
```

Artifacts are written to `dist/`.

## Troubleshooting

### `config already exists`

You already have `.dpx.yaml` or legacy `.dopx.yaml` in the directory.

### `no candidate files found`

DPX did not find a file matching its discovery patterns in the current directory.

### `password metadata missing` or decryption failed

Possible causes:
- wrong password
- tampered `.dpx` file
- corrupted payload

### `age` decrypt fails

Possible causes:
- wrong identity file
- the file was encrypted for a different recipient
- the required private key file does not exist locally

## Repository Hygiene

Do not commit:
- plaintext `.env` secrets
- generated `.dpx` secret files
- local private keys
- build outputs

Use a `.gitignore` for local artifacts and secrets.
