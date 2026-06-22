# Role: SyncManager

**Tier:** Manager  
**Status:** 🔴 Not yet extracted — logic currently inline in `POST /sync/` in `main.py`  
**Target file:** `backend/agents/sync_manager.py`  
**Owning Team:** Team Alpha  
**Reports to:** API Layer  
**Supervises:** RssParserAgent, NvdAgent, ScraperAgent, StorageAgent, CveReviewer

---

## Purpose

The SyncManager owns the full CVE ingestion pipeline. When the API receives a sync request, it hands the work to SyncManager, which decides which sources to call, sequences the worker calls, passes each result through CveReviewer, and persists only the validated records.

---

## Workflow

```
API POST /sync/
    → SyncManager.run_sync(feeds, scrapers, db)
        ├── For each NVD feed:     NvdAgent.fetch()
        ├── For each RSS feed:     RssParserAgent.fetch()
        ├── For each scraper:      ScraperAgent.fetch()
        │
        ├── For each raw CVE result:
        │       CveReviewer.review_cve()  ← gate
        │       if passed: StorageAgent.upsert_cve()
        │       if failed: log warning, skip
        │
        └── Return SyncResult (ingested_count, skipped_count, warnings)
```

---

## Responsibilities

| # | Responsibility |
|---|---|
| 1 | Receive feed + scraper config lists from the API route |
| 2 | Dispatch each source to the correct worker agent |
| 3 | Pass each parsed CVE through CveReviewer before storage |
| 4 | Call StorageAgent to upsert validated CVEs |
| 5 | After sync, call AlertManager to evaluate notification triggers |
| 6 | Return a structured SyncResult to the API layer |
| 7 | Never implement parsing or HTTP logic directly |

---

## What SyncManager Must NOT Do

- Fetch URLs or parse documents directly.
- Write to the database directly — delegate to StorageAgent.
- Skip the CveReviewer gate, even for trusted sources like NVD.
- Raise HTTP exceptions — only Python exceptions.
