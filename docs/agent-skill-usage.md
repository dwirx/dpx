# Agent Usage Guide - DPX Password Skill

Dokumen ini menjelaskan cara memakai `skill/SKILL.md` saat agent menangani task password di DPX.

## Kapan Dipakai

Pakai skill ini jika user meminta salah satu:

1. Generate password aman.
2. Ganti password pada file `.dpx`.
3. Ganti password token inline `ENC[...]`.
4. Menjalankan flow password lewat TUI.

## Alur Kerja Singkat untuk Agent

1. Validasi kebutuhan user.
2. Sinkronkan command dengan output `dpx --help`.
3. Pilih command:
   - `dpx genpass` untuk generate saja
   - `dpx repassword` untuk rotasi password file
4. Jalankan command dan rangkum hasil.
5. Jika user minta, jalankan test.

## Peta Command

### Hanya generate password

```bash
dpx genpass --length 32
```

### Rotasi password manual

```bash
dpx repassword secret.env.dpx
```

### Rotasi password + auto-generate

```bash
dpx repassword secret.env.dpx --old-password 'old' --generate-password --password-length 32
```

### Rotasi password ke file output baru

```bash
dpx repassword secret.env.dpx --old-password 'old' --generate-password --out secret.env.rotated.dpx
```

## TUI Equivalents

Jalankan:

```bash
dpx tui
```

Gunakan menu:

1. `Generate Password`
2. `Repassword (Manual)`
3. `Repassword (Generate)`

## Konvensi Respons Agent

Agar enak dipakai user, respons agent sebaiknya selalu memuat:

1. Apa yang dijalankan.
2. File output.
3. Status clipboard.
4. Saran next-step (misal test/build) jika relevan.

## Keamanan

1. Jangan menuliskan password input user ke log.
2. Password generated tampilkan seperlunya.
3. Jika clipboard gagal, jangan fail total; beri warning.

## Verifikasi yang Disarankan

Jika user meminta verifikasi:

```bash
GOCACHE=/tmp/go-cache go test ./...
```

Untuk environment sandbox terbatas, pengaturan `GOCACHE` wajib agar test tidak gagal karena cache path read-only.
