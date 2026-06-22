# Role: NvdAgent

**Tier:** Worker  
**Status:** 🟡 Logic exists in `backend/rss_parser.py` — needs thin wrapper class  
**Target file:** `backend/agents/nvd_agent.py`  
**Owning Team:** Team Alpha  
**Reports to:** SyncManager

---

## Purpose

Fetches CVE records from the NVD API 2.0 (JSON) and returns real CVSS scores, severity, and vendor/product data derived from CPE strings. This is the highest-quality data source and takes priority over RSS feed data.

---

## Method: `fetch(pub_start_date: datetime) → list[dict]`

Wraps `rss_parser.fetch_nvd_api(pub_start_date)`.

**Rate limiting:** NVD enforces 5 requests per 30 seconds. The existing implementation sleeps 6.5s between paginated requests. Do not remove this.

**Pagination:** Fetches up to 2000 results per request, auto-paginates.

**EPSS enrichment:** Only fetches EPSS scores from FIRST.org for CVEs published within the last 30 days (performance optimisation — do not change).

Returns same dict shape as RssParserAgent.

---

## What NvdAgent Must NOT Do

- Remove the 6.5s rate-limit sleep between NVD requests.
- Write to the database.
- Bypass the 2-year lookback minimum enforced in the existing code.
