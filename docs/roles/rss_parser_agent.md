# Role: RssParserAgent

**Tier:** Worker  
**Status:** 🟡 Logic exists in `backend/rss_parser.py` — needs thin wrapper class  
**Target file:** `backend/agents/rss_parser_agent.py` (wraps existing functions)  
**Owning Team:** Team Alpha  
**Reports to:** SyncManager

---

## Purpose

Fetches and parses a single RSS/Atom feed URL and returns a list of raw CVE dicts. The heavy lifting already exists in `rss_parser.fetch_and_parse_rss()` — this agent is a clean wrapper that the SyncManager calls by interface.

---

## Method: `fetch(url: str) → list[dict]`

Calls `rss_parser.fetch_and_parse_rss(url)` and normalises the result into a consistent dict shape:

```python
{
    "cve_id": str,
    "title": str,
    "description": str,
    "published_date": datetime | None,
    "reference_url": str,
    "rss_source": str,
    "vendor": str,
    "product": str,
    "severity": str,        # may be "Unknown" — NvdAgent enriches this
    "cvss_score": float | None,
}
```

Raises `FetchError` on HTTP failure (caught by SyncManager, which logs and continues).

---

## What RssParserAgent Must NOT Do

- Write to the database.
- Call NvdAgent, ScraperAgent, or StorageAgent.
- Validate the CVE data — that is CveReviewer's job.
- Implement vendor/product inference — `_infer_vendor_product()` is called by the existing function; keep it there.
