# 🔐 Env Inline Workflow (Detailed)

Panduan ini menjelaskan alur lengkap enkripsi `.env` inline dengan format `ENC[...]` di DPX.

## 🎯 Tujuan

Gunakan mode inline kalau Anda ingin:
- menjaga struktur file `.env` tetap familiar
- mengenkripsi hanya key sensitif (bukan seluruh file)
- tetap bisa baca key tertentu via CLI tanpa menulis plaintext baru

## 🧩 Format Token

DPX menggunakan dua format utama:
- `ENC[age:...]` untuk mode public-key (`age`)
- `ENC[pwd:v1:...]` untuk mode password (Argon2id + XChaCha20-Poly1305)

## 🚀 Alur Utama

### 1) Enkripsi key terpilih

```bash
dpx env encrypt .env --mode age --keys API_KEY,JWT_SECRET
# atau

dpx env encrypt .env --mode password --keys API_KEY --password 'secret'
```

Hasil:
- key terpilih berubah jadi `ENC[...]`
- key lain tetap plaintext
- komentar file tetap dipertahankan
- output default: `<file>.dpx`

### 2) Dekripsi token inline

```bash
dpx env decrypt .env.dpx --identity ~/.config/dpx/age-keys.txt
# atau

dpx env decrypt .env.dpx --password 'secret'
```

### 3) Baca key tanpa menulis file plaintext

```bash
dpx env list .env.dpx --password 'secret'
dpx env get .env.dpx --key API_KEY --password 'secret'
```

### 4) Update/tambah satu key langsung

```bash
# Tulis plaintext
dpx env set .env --key DEBUG --value true

# Tulis terenkripsi
dpx env set .env.dpx --key API_KEY --value 'new-key' --encrypt --mode age
```

Catatan:
- default update in-place (file yang sama)
- gunakan `--out` kalau ingin file output terpisah
- mode password akan minta konfirmasi password saat tidak di-pass via flag

### 5) Rotasi recipient mode age

```bash
dpx env updatekeys .env.dpx \
  --recipient age1new...,age1team... \
  --identity ~/.config/dpx/age-keys.txt
```

Opsional batasi key:

```bash
dpx env updatekeys .env.dpx --recipient age1new... --keys API_KEY,JWT_SECRET
```

## 🧪 Validasi Cepat

Untuk cek nilai tetap bisa dipakai aplikasi:

```bash
dpx run .env.dpx --password 'secret' -- node app.js
```

## ✅ Best Practice

- simpan private key di luar repo
- gunakan `dpx policy check .env` untuk deteksi plaintext sensitif
- gunakan `env updatekeys` saat rotasi akses tim
- pisahkan mode `age` (tim) vs `password` (lokal sementara) sesuai kebutuhan
