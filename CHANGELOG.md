# Changelog

All notable changes to Vnotice (CVE Monitoring App) are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this project
uses [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).

## [1.0.0] — 2026-07-02

First tagged release. Baseline of the CVE threat-monitoring platform.

### Core
- FastAPI backend (SQLite / PostgreSQL) + Next.js 14 dashboard.
- Feed ingestion: RSS/Atom, NVD API 2.0, Splunk, Check Point, and custom regex
  web scrapers. Per-source rebuild files under `backend/data/`.
- CVE list API with severity/vendor/product/search filters, pagination, EPSS,
  a short-TTL response cache, and a `days=N` recency filter.
- JWT auth; multi-user frontend profiles mirrored server-side to `app_state`.

### Notifications
- Channels: Teams, Discord, Telegram, Email (SMTP), SMS (Twilio), and LINE
  (Messaging API broadcast). Per-channel test endpoints.
- Trigger evaluation runs after each sync (keyword / vendor / product /
  min-severity / min-CVSS).
- All channel secrets encrypted at rest (Fernet via `EncryptedText`).

### Durability
- Self-healing additive schema migration on startup: missing columns are
  `ALTER TABLE`-added from the ORM models, so a version bump that adds a field
  no longer requires a manual migration or risks lost config.
- Database file lives outside the repo (gitignored); startup uses additive
  `create_all()` only, plus a rebuild-from-source-files fallback if the CVE
  table is ever empty. Pre-deploy and daily DB backups.

[1.0.0]: https://github.com/darkhager/vnotice/releases/tag/v1.0.0
