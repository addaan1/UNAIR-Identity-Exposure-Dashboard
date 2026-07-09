# UNAIR Identity Exposure Intelligence Dashboard

Dashboard intelijen paparan identitas digital untuk domain `unair.ac.id` dan subdomain terkait. Proyek ini dibangun sebagai alat defensive security untuk membantu pemantauan, prioritas mitigasi, dan tindak lanjut temuan identitas yang terpapar.

## Initial Scope

- Django web dashboard
- PostgreSQL database
- Docker Compose runtime
- Safe dummy dataset until authorized real data is available
- Masked display and sanitized export by default
- Risk scoring, identity matching, domain risk mapping, and remediation tracking

## Data Safety

This project must not store or display raw passwords, cookies, tokens, or secrets. Dummy data is synthetic and real datasets must only come from authorized sources.
