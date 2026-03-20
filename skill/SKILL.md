# DPX Password & Rotation Skill

Skill ini adalah panduan operasional untuk agent saat menangani fitur password di DPX.
Fokusnya: cepat, aman, konsisten dengan command aktual.

## Tujuan Skill

Gunakan skill ini untuk:

1. Generate password kuat (`genpass`).
2. Rotasi password file terenkripsi (`repassword`).
3. Menjalankan flow yang sama dari TUI.
4. Memberi output agent yang jelas dan siap eksekusi user.

## Batasan Scope

Skill ini hanya untuk mode `password`.

Di luar scope:

1. Rotasi recipient `age` (`dpx env updatekeys`).
2. Rotasi keypair age global (`dpx rotate`).

Jika user meminta flow `age`, arahkan ke command di atas.

## Sumber Kebenaran (Wajib Sinkron)

Sebelum mengeksekusi perubahan dokumentasi/otomasi:

1. Cek output `dpx --help`.
2. Cek README project.
3. Pastikan command/flag yang ditulis di respons sama persis dengan help.

## Command Referensi (Aktual)

### Generate password

```bash
dpx genpass
```

```bash
dpx genpass --length 32
```

```bash
dpx genpass --length 32 --copy-password=false
```

### Repassword manual

```bash
dpx repassword <file>
```

```bash
dpx repassword <file> --old-password 'old' --new-password 'new'
```

### Repassword generate

```bash
dpx repassword <file> --old-password 'old' --generate-password --password-length 32
```

### Repassword ke file output lain

```bash
dpx repassword <file> --old-password 'old' --generate-password --out <output-file>
```

### TUI menu yang relevan

```bash
dpx tui
```

Menu:

1. `Generate Password`
2. `Repassword (Manual)`
3. `Repassword (Generate)`

## Parameter Penting

`genpass`:

1. `--length` rentang `16..128` (default `28`).
2. `--copy-password` default `true`.

`repassword`:

1. `--old-password`
2. `--new-password` atau `--generate-password` (mutually exclusive)
3. `--password-length` untuk mode generate
4. `--copy-password` default `true` (saat generate)
5. `--kdf-profile` (`balanced|hardened|paranoid`)
6. `--out` (opsional, default overwrite input)

## Decision Flow untuk Agent

1. Jika user hanya butuh password baru:
   - jalankan `genpass`.
2. Jika user butuh ganti password file:
   - jalankan `repassword`.
3. Jika file mode `age`:
   - hentikan flow ini, arahkan ke `env updatekeys` / `rotate`.
4. Jika clipboard gagal:
   - tetap sukseskan flow, laporkan warning.

## Output Standar Agent

Saat selesai, agent wajib melaporkan:

1. Command yang dijalankan.
2. File yang terdampak.
3. Status copy clipboard.
4. Hasil verifikasi/test jika diminta user.

## Guardrails Keamanan

1. Jangan echo password user (lama/baru) di log.
2. Password generated boleh ditampilkan sekali untuk user.
3. Jangan menyimpan password ke file sementara selain kebutuhan command internal.
4. Jangan menjalankan command destruktif di luar permintaan user.

## Troubleshooting Cepat

### Clipboard gagal

Gejala:
- `Clipboard copy failed: ...`

Langkah:
1. Jalankan ulang dengan `--copy-password=false`.
2. Atau install tool clipboard:
   - Linux: `wl-copy` / `xclip` / `xsel`
   - macOS: `pbcopy`
   - Windows: `clip`

### `repassword only supports password-mode files`

Artinya file bukan mode password.
Gunakan flow `age`.

### `no inline ENC tokens found`

Artinya file bukan envelope `.dpx` dan tidak berisi token inline password.
Cek path dan format file.

## Checklist Eksekusi Agent (Praktis)

1. Tentukan mode: `genpass` atau `repassword`.
2. Jika `repassword`, konfirmasi target file dan strategi output (`overwrite` / `--out`).
3. Eksekusi command.
4. Laporkan hasil singkat + warning penting.
5. Jika diminta validasi, jalankan test (`go test ./...`) dan laporkan.

## Maintenance Skill

Setiap ada perubahan command/flag di DPX:

1. Update bagian `Command Referensi`.
2. Update `Parameter Penting`.
3. Update `Decision Flow` bila behavior berubah.
4. Tambahkan contoh command baru.
