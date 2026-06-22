# Team Gamma — Data & Storage

**Scope:** Database schema, ORM models, StorageAgent, migrations

## Files Owned
`backend/models.py` · `backend/database.py` · `backend/agents/storage_agent.py`

## Current State
All four models are stable: `User`, `CVE`, `UserConfig`, `NotificationTrigger`.  
`UserConfig` has `feeds_config` and `scrapers_config` JSON columns — they exist but are never saved back from the API (P3 fix needed by Alpha).

## Standards
- All schema changes need Gamma lead review.
- New non-nullable columns require a migration script (raw SQL in `docs/migrations/`).
- `Base.metadata.create_all()` is called at startup — verify it works after every schema change.
- StorageAgent is the only component that writes CVE rows — Alpha routes all CVE writes through it.

## Key Schema Notes
- `CVE` has unique constraint on `(cve_id, rss_source)` — same CVE can appear once per source.
- `UserConfig` feeds/scrapers are stored as JSON arrays — no normalisation needed for v1.
- `NotificationTrigger` check constraint: at least one of keyword/vendor/product/min_severity/min_cvss must be set.
