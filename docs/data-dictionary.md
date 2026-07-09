# Data Dictionary

The dashboard accepts authorized CSV data with this minimum structure.

| Field | Type | Notes |
| --- | --- | --- |
| `source_id` | string | Source-local identifier. Not required to be globally unique. |
| `observed_at` | ISO datetime | Timestamp of the observed exposure. Naive timestamps use `Asia/Jakarta`. |
| `url` | string | Login URL or related URL. Only `unair.ac.id` and subdomains are imported. |
| `username` | string | Masked before display. |
| `email` | string | Masked before display. |
| `exposure_types` | comma separated string | Examples: `password`, `cookie`, `token`, `sso`, `academic`, `admin`. |
| `password_present` | boolean | Stored as indicator only. Raw password is never stored. |
| `cookie_present` | boolean | Stored as indicator only. Raw cookie is never stored. |
| `token_present` | boolean | Stored as indicator only. Raw token is never stored. |
| `source_label` | string | Import batch/source label. |
| `unit_hint` | string | Optional unit or faculty hint from authorized context. |

## Sanitization Rules

- Raw passwords, cookies, tokens, and secrets are not part of the accepted schema.
- Email and username are masked before dashboard display and CSV export.
- Identity matching uses salted hashes derived from email or username context.
- Export includes summary indicators and masked evidence only.
- Unknown account or unit status remains `unknown` or `needs_validation`.
