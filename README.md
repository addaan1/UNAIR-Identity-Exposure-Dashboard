# UNAIR Identity Exposure Intelligence Dashboard

Dashboard intelijen paparan identitas digital untuk domain `unair.ac.id` dan subdomain terkait. Proyek ini dibangun sebagai alat defensive security untuk membantu pemantauan, prioritas mitigasi, dan tindak lanjut temuan identitas yang terpapar.

## Scope

- Django dashboard with authentication and simple role groups.
- PostgreSQL runtime through Docker Compose.
- Safe dummy dataset until authorized real data is available.
- Domain and subdomain risk mapping.
- Identity matching, masking, deduplication, and risk scoring.
- High-risk list, remediation tracker, audit log, and sanitized CSV export.

## Quick Start

```bash
copy .env.example .env
docker compose up --build
```

In another terminal:

```bash
docker compose exec web python manage.py seed_dummy_data --reset --create-demo-users
```

Open `http://localhost:8000`.

Demo users:

- `admin_demo`
- `analyst_demo`
- `reviewer_demo`

Use the value of `DEMO_PASSWORD` from `.env`.


## UI Revision Notes

The dashboard interface has been revised to use a light Universitas Airlangga institutional theme instead of a dark cyber theme. Main UI updates include:

- Light main workspace with UNAIR blue and gold accents.
- Collapsible sidebar with localStorage persistence.
- Cleaner topbar, KPI cards, tables, chart cards, filters, and login page.
- More professional wording for executive and operational users.
- Template bug fixes for risk score display and table empty-state column spans.
- Chart.js palette adjusted for light-mode readability.

## Management Commands

```bash
python manage.py seed_dummy_data
python manage.py import_exposures data/dummy_exposures.csv --source authorized-sample --reset
python manage.py recompute_risk_scores
python manage.py setup_roles --create-demo-users
```

## CSV Import Fields

Minimum accepted columns:

```text
source_id,observed_at,url,username,email,exposure_types,password_present,cookie_present,token_present,source_label,unit_hint
```

Only `unair.ac.id` and subdomains are imported. Non-UNAIR rows are skipped.

## Data Safety

This project must not store or display raw passwords, cookies, tokens, or secrets. The import schema stores indicators only, identities are masked in the UI and export, and identity matching uses salted hashes. Real datasets must only come from authorized sources.

## Documentation

- [Data dictionary](docs/data-dictionary.md)
- [Handover notes](docs/handover.md)
