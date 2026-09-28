"""Threat Summary: extract details + AI summary/verification for the CVEs the
admin picked in Settings → Threat Summary Management (sources, and optionally
specific products under each, like the Threat Stream filter).

Results live in the cve_insights table, one row per CVE number, linked to
`cves` by cve_id. Two dates per row: extracted_at (details pulled from the
CVE.org record) and ai_checked_at (AI summary + per-field check).

Run every 10 minutes by vnotice-threat-summary.timer; each run handles at most
BATCH CVE numbers, newest first, so a wide scope backfills gradually instead of
firing thousands of CVE.org / AI requests at once.

    python threat_summary.py        # one batch
"""
import json
import logging
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, and_

import ai_access
import llm
import models
from database import SessionLocal
from rss_parser import RSSIngestionService

logger = logging.getLogger("vnotice.threat_summary")

SCOPE_KEY = "summary_scope"
DETAIL_FIELDS = ("affected_versions", "affected_conditions", "mitigation",
                 "remediation", "fixed_versions", "iocs")
BATCH = 15
BACKFILL_DAYS = 30        # scope applies to CVEs added in the last N days (and every new one)
REFRESH_DAYS = 7          # vendors add fix info after publication: re-extract after a week

PROMPT = """You are checking an automated extraction of vulnerability details against the vendor's own CVE record,
and writing a short summary for a security operations team.
Use ONLY the SOURCE below -- never outside knowledge, never guess.

Field meanings:
- affected_versions: affected products and versions / version ranges
- affected_conditions: configuration or conditions required for a system to be vulnerable (may be stated in the description)
- fixed_versions: versions in which the issue is fixed
- remediation: the vendor's fix (upgrade / patch instructions)
- mitigation: workarounds that reduce risk without fixing it
- iocs: indicators of compromise (file hashes, IPs, domains) stated in the source

For each field give a status:
- "ok": consistent with the source and nothing important for that field is left out
- "incomplete": correct, but the source contains more for that field
- "incorrect": contradicts the source or is not supported by it
- "missing": the extraction is empty but the source DOES contain this information
- "absent": the extraction is empty and the source has nothing for it either

Reply with JSON only, no prose, exactly this shape:
{"summary": "<3-5 sentences: what is vulnerable, how it is exploited, impact, and what to do>",
 "fields": {"affected_versions": {"status": "...", "note": "<= 200 chars", "suggested": "<corrected value copied or condensed from the SOURCE, or null>"}, ...same for affected_conditions, fixed_versions, remediation, mitigation, iocs}}
"suggested" must be null for "ok" and "absent".

CVE (from the vulnerability database):
%s

SOURCE (CVE.org record, JSON):
%s

EXTRACTED:
%s"""


def _utc(dt):
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


# ─── scope (admin setting, stored in app_state) ───

def get_scope(db):
    row = db.query(models.AppState).filter(models.AppState.key == SCOPE_KEY).first()
    v = row.value if row and isinstance(row.value, dict) else {}
    return {"enabled": bool(v.get("enabled")), "sources": v.get("sources") or {}}


def save_scope(db, enabled, sources):
    """sources: {"<rss_source>": "all" | ["product", ...]}"""
    clean = {}
    for src, prods in (sources or {}).items():
        if not isinstance(src, str) or not src.strip():
            continue
        if prods == "all":
            clean[src] = "all"
        elif isinstance(prods, list) and prods:
            clean[src] = sorted({p for p in prods if isinstance(p, str) and p})
    value = {"enabled": bool(enabled), "sources": clean}
    row = db.query(models.AppState).filter(models.AppState.key == SCOPE_KEY).first()
    if row:
        row.value = value
    else:
        db.add(models.AppState(key=SCOPE_KEY, value=value))
    db.commit()
    return value


def _scope_filter(sources):
    clauses = []
    for src, prods in sources.items():
        if prods == "all":
            clauses.append(models.CVE.rss_source == src)
        else:
            clauses.append(and_(models.CVE.rss_source == src, models.CVE.product.in_(prods)))
    return or_(*clauses) if clauses else None


def _in_scope_ids(db, sources):
    """CVE numbers in scope added within BACKFILL_DAYS, newest first."""
    f = _scope_filter(sources)
    if f is None:
        return []
    since = datetime.utcnow() - timedelta(days=BACKFILL_DAYS)
    rows = (db.query(models.CVE.cve_id).filter(f, models.CVE.created_at >= since)
            .order_by(models.CVE.created_at.desc()).all())
    seen, out = set(), []
    for (cid,) in rows:
        if cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


def stats(db):
    scope = get_scope(db)
    ids = _in_scope_ids(db, scope["sources"])
    extracted = checked = errors = 0
    for i in range(0, len(ids), 500):
        for ins in db.query(models.CveInsight).filter(models.CveInsight.cve_id.in_(ids[i:i + 500])):
            extracted += ins.extracted_at is not None
            checked += ins.ai_checked_at is not None
            errors += bool(ins.ai_error)
    return {"in_scope": len(ids), "extracted": extracted, "ai_checked": checked,
            "ai_errors": errors, "ai_configured": llm.configured(), "backfill_days": BACKFILL_DAYS}


# ─── work ───

def extract(db, cve_id, force=False):
    """Pull the details from CVE.org into cve_insights (unless fresh). Returns the row or None."""
    ins = db.get(models.CveInsight, cve_id)
    fresh = ins is not None and ins.extracted_at is not None and \
        datetime.now(timezone.utc) - _utc(ins.extracted_at) <= timedelta(days=REFRESH_DAYS)
    if fresh and not force:
        return ins
    details = RSSIngestionService.fetch_cve_record_details(cve_id)
    # A failed lookup on a real CVE id stays un-extracted so the next run retries;
    # a non-CVE id (FG-IR/SVD) has no CVE.org record ever, so mark it done.
    if details is None and cve_id.startswith("CVE-"):
        return ins
    if ins is None:
        ins = models.CveInsight(cve_id=cve_id)
        db.add(ins)
    changed = any(getattr(ins, f) != (details or {}).get(f) for f in DETAIL_FIELDS)
    for f in DETAIL_FIELDS:
        setattr(ins, f, (details or {}).get(f))
    ins.extracted_at = datetime.now(timezone.utc)
    if changed:   # a verdict is only valid for the text it checked
        ins.ai_verification = ins.ai_summary = ins.ai_checked_at = ins.ai_error = None
    db.commit()
    return ins


class CheckError(Exception):
    pass


def ai_check(db, cve_id):
    """AI summary + per-field verification of the extracted details."""
    ins = db.get(models.CveInsight, cve_id)
    if ins is None or ins.extracted_at is None:
        raise CheckError("Extract the details first.")
    if not llm.configured():
        raise CheckError("No AI API key is registered yet (Settings → AI Verification).")
    record = RSSIngestionService.fetch_cve_record(cve_id)
    if record is None:
        raise CheckError("No CVE.org record to check against for this ID.")
    # Everything that reaches the prompt is read through ai_access's guarded,
    # read-only connection (vulnerability tables, allowlisted columns only).
    try:
        cve = ai_access.ai_read_cve(cve_id, ("cve_id", "title", "description", "severity",
                                             "cvss_score", "vendor", "product"))
        extracted = ai_access.ai_read_cve(cve_id, DETAIL_FIELDS, table="cve_insights")
    except ai_access.AIAccessError as e:
        raise CheckError(str(e))
    if cve is None or extracted is None:
        raise CheckError("CVE not found")
    prompt = PROMPT % (json.dumps(cve, ensure_ascii=False, default=str),
                       RSSIngestionService.cve_record_source_text(record),
                       json.dumps(extracted, ensure_ascii=False))
    try:
        reply = llm.chat([{"role": "user", "content": prompt}], max_tokens=2500, role="verify")
        start, end = reply.find("{"), reply.rfind("}")
        data = json.loads(reply[start:end + 1])
    except (llm.LLMError, ValueError) as e:
        ins.ai_error = str(e)[:500]
        db.commit()
        raise CheckError(f"AI check failed: {e}")
    fields = data.get("fields") if isinstance(data.get("fields"), dict) else {}
    fields = {f: fields.get(f) for f in DETAIL_FIELDS if isinstance(fields.get(f), dict)}
    ok = len(fields) == len(DETAIL_FIELDS) and all(v.get("status") in ("ok", "absent") for v in fields.values())
    now = datetime.now(timezone.utc)
    model = llm.public_settings().get("verify_model") or llm.public_settings().get("model") or ""
    verdict = {"status": "verified" if ok else "issues", "fields": fields,
               "model": model, "checked_at": now.isoformat()}
    ins.ai_summary = str(data.get("summary") or "").strip()[:4000] or None
    ins.ai_verification = json.dumps(verdict, ensure_ascii=False)
    ins.ai_model = model
    ins.ai_checked_at = now
    ins.ai_error = None
    db.commit()
    return ins


def public(ins, cve_id):
    """API shape for one insight row (None-safe)."""
    out = {f: getattr(ins, f, None) if ins else None for f in DETAIL_FIELDS}
    out.update({
        "cve_id": cve_id,
        "source": "https://www.cve.org/CVERecord?id=" + cve_id if cve_id.startswith("CVE-") else None,
        "extracted_at": _utc(ins.extracted_at).isoformat() if ins and ins.extracted_at else None,
        "ai_summary": ins.ai_summary if ins else None,
        "verification": json.loads(ins.ai_verification) if ins and ins.ai_verification else None,
        "ai_checked_at": _utc(ins.ai_checked_at).isoformat() if ins and ins.ai_checked_at else None,
        "ai_error": ins.ai_error if ins else None,
        "ai_configured": llm.configured(),
    })
    return out


def clear_errors(db):
    n = db.query(models.CveInsight).filter(models.CveInsight.ai_error.isnot(None))         .update({models.CveInsight.ai_error: None}, synchronize_session=False)
    db.commit()
    return n


def run(limit=BATCH):
    db = SessionLocal()
    try:
        scope = get_scope(db)
        if not scope["enabled"] or not scope["sources"]:
            return "threat summary off (no scope selected)"
        ids = _in_scope_ids(db, scope["sources"])
        use_ai = llm.configured()
        done = {i.cve_id: i for i in db.query(models.CveInsight).filter(models.CveInsight.cve_id.in_(ids[:5000]))}
        todo = []
        for cid in ids:
            ins = done.get(cid)
            needs_extract = ins is None or ins.extracted_at is None or \
                datetime.now(timezone.utc) - _utc(ins.extracted_at) > timedelta(days=REFRESH_DAYS)
            # an AI failure is not retried automatically (it would eat every batch);
            # it is cleared when the details change, or by "Retry failed" in the admin page
            needs_ai = use_ai and (ins is None or ins.ai_checked_at is None) and not (
                ins is not None and ins.ai_error)
            if needs_extract or needs_ai:
                todo.append(cid)
            if len(todo) >= limit:
                break
        n_ext = n_ai = n_err = 0
        for cid in todo:
            try:
                before = done.get(cid)
                had = before.extracted_at if before else None
                ins = extract(db, cid)
                n_ext += bool(ins and ins.extracted_at != had)
                if use_ai and ins is not None and ins.extracted_at is not None and ins.ai_checked_at is None:
                    ai_check(db, cid)
                    n_ai += 1
            except CheckError as e:
                n_err += 1
                logger.warning(f"threat summary {cid}: {e}")
            except Exception as e:   # one bad CVE must not stop the batch
                db.rollback()
                n_err += 1
                logger.error(f"threat summary {cid}: {e!r}")
        return (f"{len(ids)} in scope · extracted {n_ext} · AI checked {n_ai} · errors {n_err}"
                + ("" if use_ai else " · AI not configured (extraction only)"))
    finally:
        db.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(f"[{datetime.utcnow().isoformat()}] {run()}")
