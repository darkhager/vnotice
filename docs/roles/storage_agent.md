# Role: StorageAgent

**Tier:** Worker  
**Status:** 🔴 Not yet created — DB writes currently inline in `main.py`  
**Target file:** `backend/agents/storage_agent.py`  
**Owning Team:** Team Gamma  
**Reports to:** SyncManager

---

## Purpose

Owns all database read/write operations for CVE records. Centralises the upsert logic (insert if new, skip if duplicate) that is currently scattered through `main.py`'s `/sync/` route.

---

## Methods

### `upsert_cve(db: Session, cve_data: dict) → tuple[CVE, bool]`

Inserts a new CVE row or skips if `(cve_id, rss_source)` already exists.  
Returns `(cve_object, was_created)`.  
The unique constraint on `(cve_id, rss_source)` is enforced by the DB — StorageAgent catches `IntegrityError` and returns the existing row with `was_created=False`.

### `get_cves(db, severity, vendor, product, search, skip, limit) → list[CVE]`

Query wrapper for `GET /cves/` — currently inline in `main.py`. Centralise here.

### `get_cve_by_id(db, cve_id) → CVE | None`

Single record lookup.

---

## What StorageAgent Must NOT Do

- Validate CVE data — that is CveReviewer's job.
- Call RSS/NVD/scraper agents.
- Handle HTTP requests.
