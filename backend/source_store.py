"""Per-source JSON file store — one file per feed source.

Acts as both the per-source separation the deployment wants and a fail-safe for
the SQLite DB:
  * every sync writes each source's CVEs to data/sources/<slug>.json (and the DB)
  * /cves/ falls back to these files when the DB query raises
  * on startup, an empty DB is rebuilt from these files

Files are the durable copy; the DB is the fast query layer rebuilt from them.
Records are stored JSON-safe (datetimes as ISO strings) and CVEResponse-shaped
(each carries a deterministic `id` so the API can serve them directly).
"""
import json
import os
import re
import uuid
import tempfile
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

STORE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "sources")

# Fields persisted per record (mirror the columns the API/DB care about).
_FIELDS = (
    "cve_id", "title", "description", "severity", "cvss_score", "epss",
    "published_date", "updated_date", "vendor", "product", "reference_url",
    "keywords",
)


def _slug(source_name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", (source_name or "").lower()).strip("_")
    return s or "unknown"


def _path(source_name: str) -> str:
    return os.path.join(STORE_DIR, _slug(source_name) + ".json")


def _norm(item: dict, source_name: str) -> dict:
    """Normalize a parsed CVE dict into a JSON-safe, CVEResponse-shaped record."""
    rec = {k: item.get(k) for k in _FIELDS}
    for k in ("published_date", "updated_date"):
        v = rec.get(k)
        if isinstance(v, datetime):
            rec[k] = v.isoformat()
    for k in ("cvss_score", "epss"):  # coerce Decimal/str (DB rows) -> float
        if rec.get(k) is not None:
            try:
                rec[k] = float(rec[k])
            except (TypeError, ValueError):
                rec[k] = None
    if not rec.get("updated_date"):
        rec["updated_date"] = rec.get("published_date")
    rec["rss_source"] = source_name
    rec["created_at"] = datetime.utcnow().isoformat()
    # Stable synthetic UUID so the API can return file records directly.
    rec["id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{source_name}:{rec.get('cve_id')}"))
    return rec


def _atomic_write(path: str, data) -> None:
    os.makedirs(STORE_DIR, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=STORE_DIR, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, default=str)
        os.replace(tmp, path)
    except Exception as e:
        logger.error(f"source_store atomic write failed for {path}: {e}")
        if os.path.exists(tmp):
            os.remove(tmp)


def read_source(source_name: str) -> list:
    try:
        with open(_path(source_name), encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []


def write_source(source_name: str, items: list) -> None:
    """Merge `items` into the source's file (dedupe by cve_id), atomically."""
    if not items:
        return
    merged = {r.get("cve_id"): r for r in read_source(source_name)}
    for it in items:
        rec = _norm(it, source_name)
        merged[rec["cve_id"]] = rec
    _atomic_write(_path(source_name), list(merged.values()))


def read_all() -> list:
    out = []
    if not os.path.isdir(STORE_DIR):
        return out
    for fn in os.listdir(STORE_DIR):
        if fn.endswith(".json"):
            try:
                with open(os.path.join(STORE_DIR, fn), encoding="utf-8") as f:
                    out.extend(json.load(f))
            except (json.JSONDecodeError, OSError):
                continue
    return out


def query_fallback(severity=None, vendor=None, product=None, search=None, skip=0, limit=20) -> list:
    """Degraded /cves/ read served from files when the DB is unavailable."""
    sev = [s.lower() for s in severity] if severity else None
    def keep(r):
        if sev and "all" not in sev and (r.get("severity") or "").lower() not in sev:
            return False
        if vendor and vendor.lower() not in (r.get("vendor") or "").lower():
            return False
        if product and product.lower() not in (r.get("product") or "").lower():
            return False
        if search:
            q = search.lower()
            if q not in (r.get("title") or "").lower() and q not in (r.get("description") or "").lower():
                return False
        return True
    recs = [r for r in read_all() if keep(r)]
    recs.sort(key=lambda r: r.get("published_date") or "", reverse=True)
    return recs[skip: skip + limit]


def record_to_cve_kwargs(rec: dict) -> dict:
    """Map a file record back to models.CVE constructor kwargs (parse dates)."""
    def _dt(v):
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v)
            except ValueError:
                return None
        return v
    return {
        "cve_id": rec.get("cve_id"),
        "title": rec.get("title") or rec.get("cve_id") or "Unknown",
        "description": rec.get("description"),
        "severity": rec.get("severity"),
        "cvss_score": rec.get("cvss_score"),
        "epss": rec.get("epss"),
        "published_date": _dt(rec.get("published_date")),
        "updated_date": _dt(rec.get("updated_date") or rec.get("published_date")),
        "vendor": rec.get("vendor"),
        "product": rec.get("product"),
        "reference_url": rec.get("reference_url"),
        "rss_source": rec.get("rss_source"),
        "keywords": rec.get("keywords") or [],
    }
