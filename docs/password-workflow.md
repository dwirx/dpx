# DPX Password Workflow (CLI + TUI)

Dokumen ini menjelaskan alur lengkap untuk:
- generate password kuat
- ganti password file terenkripsi
- menggunakan fitur yang sama dari CLI maupun TUI

## Ringkasan Fitur

DPX sekarang mendukung:

1. `dpx genpass` untuk membuat password kuat.
2. `dpx repassword` untuk rotasi password pada:
   - file `.dpx` mode `password`
   - file inline `ENC[...]` mode `password`
3. Auto-copy password hasil generate ke clipboard (bisa dimatikan).
4. Integrasi TUI:
   - `Repassword (Manual)`
   - `Repassword (Generate)`
   - `Generate Password`

## 1) Generate Password (CLI)

Perintah dasar:

```bash
dpx genpass
```

Perintah dengan panjang custom:

```bash
dpx genpass --length 32
```

Tanpa copy clipboard:

```bash
dpx genpass --copy-password=false
```

Catatan:
- Panjang password valid: `16` sampai `128`.
- Default panjang: `28`.
- Secara default password akan dicoba copy ke clipboard.

## 2) Repassword File `.dpx` (CLI)

### Opsi manual (prompt)

```bash
dpx repassword secrets.env.dpx
```

Alur:
1. Input current password.
2. Input new password.
3. Konfirmasi new password.
4. File ditulis ulang (default overwrite file input).

### Opsi manual via flag

```bash
dpx repassword secrets.env.dpx \
  --old-password 'old-pass' \
  --new-password 'new-pass'
```

### Opsi generate otomatis

```bash
dpx repassword secrets.env.dpx \
  --old-password 'old-pass' \
  --generate-password \
  --password-length 32
```

### Output ke file lain

```bash
dpx repassword secrets.env.dpx \
  --old-password 'old-pass' \
  --generate-password \
  --out secrets.env.rotated.dpx
```

### KDF profile saat re-encrypt

```bash
dpx repassword secrets.env.dpx \
  --old-password 'old-pass' \
  --new-password 'new-pass' \
  --kdf-profile hardened
```

Pilihan profile: `balanced`, `hardened`, `paranoid`.

## 3) Repassword Inline Env Token (CLI)

Berlaku jika file berisi token `ENC[...]` mode password.

```bash
dpx repassword .env.dpx \
  --old-password 'old-pass' \
  --generate-password
```

Hasil:
- token inline password dienkripsi ulang dengan password baru
- key mode `age` tidak disentuh

## 4) Penggunaan dari TUI

Jalankan:

```bash
dpx tui
```

Pilih salah satu menu:

1. `Generate Password`
2. `Repassword (Manual)`
3. `Repassword (Generate)`

Menu TUI akan meneruskan flow ke command yang sama di CLI, jadi behavior konsisten.

## 5) Clipboard Behavior

Saat generate password:
- DPX akan mencoba copy ke clipboard.
- Jika command clipboard tidak tersedia, proses tetap sukses dan DPX hanya menampilkan warning.

Implementasi command clipboard:
- macOS: `pbcopy`
- Windows: `clip`
- Linux: `wl-copy`, `xclip`, atau `xsel` (otomatis mencoba berurutan)

## 6) Best Practice Operasional

1. Gunakan `--generate-password` untuk password produksi.
2. Gunakan panjang minimal `24`, rekomendasi `32`.
3. Simpan password di password manager, bukan di shell history.
4. Setelah repassword, jalankan test aplikasi yang membaca secret tersebut.
5. Untuk tim, pertimbangkan mode `age` agar rotasi akses lebih mudah.

## 7) Troubleshooting

### "Clipboard copy failed"

Penyebab umum:
- tool clipboard belum terpasang
- tidak ada session GUI/Wayland/X11 aktif

Mitigasi:
- install tool clipboard (`wl-copy`/`xclip`/`xsel`)
- atau jalankan dengan `--copy-password=false`

### "repassword only supports password-mode files"

Artinya file `.dpx` memakai mode `age`.
Gunakan `dpx env updatekeys` / `dpx rotate` untuk flow age.

### "no inline ENC tokens found"

File bukan envelope `.dpx` dan tidak berisi token inline yang relevan.
Pastikan path benar dan file memang sudah dienkripsi mode password.
