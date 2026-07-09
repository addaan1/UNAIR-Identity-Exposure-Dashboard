# UI Redesign Summary

Tanggal revisi: 9 Juli 2026

## Fokus Perubahan

Dashboard direvisi dari tampilan gelap/cyber-neon menjadi tampilan light mode yang lebih institusional, bersih, dan sesuai dengan konteks Universitas Airlangga.

## Perubahan Utama

- Mengubah tema utama menjadi light mode dengan warna UNAIR blue dan UNAIR gold.
- Menambahkan collapsible sidebar dengan penyimpanan preferensi melalui localStorage.
- Merapikan topbar, KPI cards, chart cards, filter bar, tabel, login page, dan remediation cards.
- Menghapus inline style yang terlalu banyak pada template utama agar desain lebih konsisten.
- Menambahkan menu sidebar yang lebih terstruktur: Overview, Intelligence, dan Response.
- Menambahkan halaman High Risk ke sidebar agar temuan prioritas mudah diakses.
- Menyesuaikan palette Chart.js agar lebih terbaca di light mode.
- Memperbaiki bug tampilan risk score dari `numeric_score` menjadi `score`.
- Memperbaiki empty-state table colspan pada halaman Identity dan High Risk.
- Memperbaiki field waktu di tabel overview dari `discovered_at` menjadi `observed_at`.

## File Utama yang Diubah

- `templates/base.html`
- `templates/exposures/overview.html`
- `templates/exposures/domain_risk.html`
- `templates/exposures/identity_exposure.html`
- `templates/exposures/high_risk.html`
- `templates/exposures/remediation.html`
- `templates/registration/login.html`
- `static/exposures/css/dashboard.css`
- `static/exposures/js/dashboard.js`
- `README.md`

## Validasi

- `python manage.py check` berhasil tanpa issue.
- `python manage.py test` berhasil: 8 tests OK.
- Render check untuk halaman `/`, `/domains/`, `/identities/`, `/high-risk/`, dan `/remediation/` berhasil dengan status HTTP 200 menggunakan Django test client.
