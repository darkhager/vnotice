# Role: CveReviewer

**Tier:** Reviewer  
**Status:** 🔴 Not yet created  
**Target file:** `backend/agents/cve_reviewer.py`  
**Owning Team:** Team Alpha (Engineering Lead approval to change)  
**Reports to:** SyncManager (only caller)

---

## Purpose

The CveReviewer validates every parsed CVE record before it is written to the database. It is stateless and never modifies data. It detects malformed, implausible, or duplicate records and classifies findings as errors (skip the record) or warnings (store but flag).

---

## Method: `review_cve(cve_data: dict) → ReviewResult`

| Check | Severity | Condition |
|---|---|---|
| Missing CVE ID | Error | `cve_id` is empty or None |
| Invalid CVE ID format | Error | Does not match `CVE-\d{4}-\d{4,}` or `CVE-FEED-\d+` or known vendor formats |
| Missing title | Warning | `title` is empty |
| CVSS out of range | Error | `cvss_score` is not None and not in 0.0–10.0 |
| Future publish date | Warning | `published_date` > today + 1 day |
| Excessively old CVE | Warning | `published_date` < today - 2 years |
| Empty description | Warning | `description` is empty or "N/A" |

**Returns:** `ReviewResult(passed, warnings, errors)` — same structure as doc-template-studio's ReviewerAgent.

---

## What CveReviewer Must NOT Do

- Modify the CVE data dict.
- Write to or read from the database.
- Call any other agent.
- Reject CVEs purely because vendor/product fields are generic (inferral happens upstream).
