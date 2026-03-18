# 🧪 Testing Report - 2026-03-18

Laporan ini mencatat verifikasi fitur DPX setelah implementasi `env set`, `env updatekeys`, `creation_rules`, `run`, dan `policy`.

## ✅ Automated Test Suite

Perintah:

```bash
go test ./...
```

Hasil:
- seluruh package lulus
- termasuk `cmd/dpx`, `internal/envcrypt`, `internal/policy`, `internal/app`

## ✅ Smoke Test End-to-End CLI

Tanggal uji: **2026-03-18**
Lingkungan: direktori sementara (`/tmp/...`) dengan binary hasil `go build ./cmd/dpx`.

Skenario yang diuji:

1. `dpx init` dan `dpx keygen`
2. `dpx env encrypt` mode password (key terpilih)
3. `dpx env list` dan `dpx env get`
4. `dpx env set` key baru dalam mode password
5. `dpx run` untuk injeksi env ke proses (`API_KEY` terbaca)
6. `dpx env decrypt` ke file output plaintext
7. `dpx env encrypt` mode age
8. `dpx env updatekeys` untuk rotasi recipient
9. verifikasi key lama gagal decrypt, key baru berhasil decrypt
10. `dpx policy check` pada plaintext (expected fail, temukan 4 key sensitif)

Ringkasan hasil:
- seluruh skenario berjalan sesuai ekspektasi
- flow rotasi recipient terbukti bekerja
- policy scanner mendeteksi secret plaintext dengan benar

## 🧾 Snapshot Output Penting

Contoh hasil real saat uji:
- `dpx env encrypt .env --mode password ...`  
  output: `Updated keys (2): API_KEY, JWT_SECRET`
- `dpx env set .env.dpx --key REDIS_PASSWORD ...`  
  output: `Env key REDIS_PASSWORD updated and encrypted (password) -> .env.dpx`
- `dpx run .env.dpx --password ...`  
  output: `sk-test-123` (nilai `API_KEY` berhasil diinjeksikan ke proses)
- `dpx env updatekeys age.env.dpx ...`  
  output: `Updated keys (1): API_KEY`
- verifikasi key lama setelah rotasi:  
  `identity did not match any of the recipients` (ini expected behavior ✅)
- `dpx policy check restored.env`:  
  menemukan 4 key sensitif plaintext (`API_KEY`, `DATABASE_URL`, `JWT_SECRET`, `REDIS_PASSWORD`)

## 🔎 Catatan Kualitas

- password flow sudah mendukung confirmation prompt saat interaktif
- inline mode menjaga komentar dan key non-target tetap utuh
- command baru sudah dilindungi validasi input utama (`--key`, `--recipient`, mode, dsb.)

## 📌 Kesimpulan

Status saat ini: **berfungsi baik** untuk workflow utama CLI dan inline env encryption.
