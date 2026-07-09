# UI Redesign Summary

## Revision: Light Institutional UI v2

Perubahan tambahan yang dilakukan pada revisi ini:

1. **Logo dan identitas UNAIR diperkuat**
   - Menambahkan `unair-crest.png` untuk logo sidebar dan login.
   - Menambahkan `unair-favicon.png` agar tab browser memakai ikon UNAIR.
   - Sidebar brand dibuat lebih besar dan lebih jelas, bukan lagi logo kecil di dalam kotak putih.

2. **Topbar user session diperbaiki**
   - Tombol `analyst_demo · Keluar` diganti menjadi kartu profil kecil dengan avatar inisial pengguna.
   - Tombol keluar dibuat ikon terpisah agar lebih rapi.

3. **Login page dibuat lebih bold dan sesuai gaya UNAIR**
   - Login sekarang memakai komposisi biru-kuning, headline besar, dan layout dua kolom.
   - Ditambahkan pesan internal access dan safe evidence agar konteks keamanan lebih jelas.

4. **Profil identitas memiliki incident drill-down**
   - Kolom jumlah insiden sekarang memiliki tombol `Lihat insiden`.
   - Setiap profil bisa dibuka untuk melihat domain, waktu observasi, jenis exposure, evidence yang dimasking, faktor risiko, skor risiko, dan link ke halaman tindak lanjut.
   - Fitur ini membantu analis memahami bagian mana yang menjadi sumber paparan, bukan hanya melihat angka total.

5. **Halaman tindak lanjut dibuat lebih impactful**
   - Ditambahkan remediation playbook: Critical, High, dan Evidence.
   - Ditambahkan value panel yang menjelaskan nilai dashboard untuk prioritas akun, validasi unit, audit penanganan, dan mitigasi spesifik.
   - Setiap antrean tindak lanjut sekarang menampilkan rekomendasi tindakan berdasarkan jenis exposure: token, cookie/session, password, atau identifier saja.

6. **Validasi teknis**
   - Project tetap mempertahankan Django view dan business logic utama.
   - Perubahan fokus pada UI, navigasi, traceability insiden, dan tampilan tindak lanjut.
