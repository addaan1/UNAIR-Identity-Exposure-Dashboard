# Handover Notes

## Local Setup

1. Copy `.env.example` to `.env`.
2. Run `docker compose up --build`.
3. Seed demo data:

```bash
docker compose exec web python manage.py seed_dummy_data --reset --create-demo-users
```

Demo users are `admin_demo`, `analyst_demo`, and `reviewer_demo`. The password is controlled by `DEMO_PASSWORD` in `.env`.

## Import Authorized Data

```bash
docker compose exec web python manage.py import_exposures data/dummy_exposures.csv --source authorized-sample --reset
docker compose exec web python manage.py recompute_risk_scores
```

Real datasets must come from authorized sources only. Do not add raw passwords, cookies, tokens, or secrets to CSV files.

## Operational Review Checklist

- Confirm all dashboard pages require login.
- Confirm CSV export is available only to `admin`, `analyst`, or `reviewer`.
- Confirm exported CSV contains masked identities and sanitized evidence.
- Review high-risk findings with score factors before remediation decisions.
- Use `needs_validation` when identity or unit mapping is uncertain.

## Backlog

- Scheduled ingestion and enrichment.
- Stronger anomaly detection after historical data exists.
- Notification workflow for new critical exposure.
- Role-specific dashboard variants.
- Integration with approved internal master data.
