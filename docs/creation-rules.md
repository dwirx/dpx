# 🧠 Creation Rules

`creation_rules` membantu DPX menerapkan default enkripsi secara konsisten per pola file.

## 📍 Lokasi Konfigurasi

Tambahkan di `.dpx.yaml`:

```yaml
policy:
  creation_rules:
    - path: ".env.production"
      mode: "age"
      encrypt_keys:
        - "API_KEY"
        - "JWT_SECRET"
```

## 🧱 Field yang Didukung

- `path`: pattern nama/path file (contoh: `.env.production`, `config/*.env`)
- `mode`: `age` atau `password`
- `encrypt_keys`: daftar key yang otomatis dipilih untuk enkripsi

## ⚙️ Efek di CLI

Saat rule match ke file target:
- `dpx env encrypt <file>`:
  - otomatis pakai `mode` rule jika `--mode` tidak diberikan
  - otomatis pakai `encrypt_keys` jika `--keys` tidak diberikan
- `dpx env set`:
  - jika key ada di `encrypt_keys`, DPX bisa auto-encrypt dengan mode rule

## 💡 Contoh Pakai

```bash
dpx env encrypt .env.production --password 'secret'
```

Dengan rule di atas, `API_KEY` dan `JWT_SECRET` akan terenkripsi walau tanpa `--keys`.

## 🔒 Rekomendasi Operasional

- buat rule per environment (`.env.dev`, `.env.staging`, `.env.production`)
- hindari wildcard terlalu luas agar tidak salah enkripsi file non-target
- kombinasikan dengan `dpx policy check` di CI untuk mencegah secret plaintext
