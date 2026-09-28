"""Matches Vnotice's ingested CVEs against the Centralize Customer Services
database's real product inventory, and writes matches into its
`vulnerability_finding` table. This is what turns "a CVE was published" into
"customer X's firewall is exposed to it" -- neither system can answer that
question alone.

Vnotice and Centralize stay two separate services with two separate
databases (no merge). This script is the only bridge between them, and it
only ever talks to Centralize through role_vnotice -- a restricted Postgres
role (see sql/vnotice_role_setup.sql in the Centralize repo) that can read
four columns of `product` and can SELECT/INSERT/UPDATE(status) on
`vulnerability_finding`. It cannot see who owns a product, or any table
besides those two.

It reads Vnotice's own CVEs over its public HTTPS /cves/ API rather than
touching cvedb.sqlite directly, for the same reason: this script may run on
a different machine than either database, and the API is the one interface
Vnotice already commits to keeping stable.

THE HARD PART (see _normalize): Vnotice's `vendor`/`product` fields are free
text scraped from RSS titles -- "Check Point" / "checkpoint" / "CheckPoint"
all occur for the same real vendor. Centralize's `product.vendor` is clean,
hand-entered data. A plain equality join would silently match almost
nothing, which is worse than no integration at all (a vulnerability tool
that quietly finds nothing looks identical to one that correctly found
nothing). So every CVE inserted as a finding carries a `notes` field that
says plainly this is a vendor-level match only, not a verified match against
the product's specific model or software version -- that still needs a
human, or a future version-range-aware pass, to confirm.

Run manually, or on a schedule wherever something can reach BOTH Vnotice's
public API and Centralize's Postgres (today: the Centralize Postgres
instance is a local-only portable install, not reachable from Vnotice's
production host, so this does not run there yet -- see CENTRALIZE_DATABASE_URL).
"""
import os
import re
import sys
from datetime import datetime
from typing import Optional

import httpx
from sqlalchemy import create_engine, text

# role_vnotice's own connection string -- see sql/vnotice_role_setup.sql in
# the Centralize repo. Never the app's own DATABASE_URL; this role has no
# access beyond the two tables/columns it was explicitly granted.
CENTRALIZE_DATABASE_URL = os.getenv("CENTRALIZE_DATABASE_URL")

# Vnotice's own public read API (no auth -- /cves/ is already unauthenticated).
VNOTICE_API_BASE = os.getenv("VNOTICE_API_BASE", "http://10.4.150.57:8080")

# Vnotice's backend terminates TLS with its own internal CA, which by
# deliberate earlier decision is not distributed to any client (see
# backend/certs/ -- "leave it untrusted, server-side only"). A plain data
# read of already-public CVE metadata doesn't need that trust chain verified.

# Vendor strings Vnotice uses as an explicit "couldn't identify a vendor"
# placeholder -- matching these against anything would be a false positive,
# not a real finding.
_NON_VENDOR_PLACEHOLDERS = {"various", "unknown", ""}

# Known abbreviations/short forms that the plain normalizer below won't catch
# because they're not just punctuation/case variants of the same word (e.g.
# an acronym). Add an entry here the day a real mismatch is found; nothing
# here is speculative -- start empty rather than guess at aliases with no
# evidence they occur in either system's data.
VENDOR_ALIASES: dict[str, str] = {}

_CENTRALIZE_SEVERITIES = {"critical", "high", "medium", "low"}


def _normalize(vendor: Optional[str]) -> str:
    """Collapse case/punctuation/whitespace variants of the same vendor name
    down to one key: "Check Point" / "checkpoint" / "CheckPoint" all become
    "checkpoint". Does not handle genuine abbreviations (see VENDOR_ALIASES).
    """
    key = re.sub(r"[^a-z0-9]", "", (vendor or "").lower())
    return VENDOR_ALIASES.get(key, key)


def _map_severity(vnotice_severity: Optional[str]) -> Optional[str]:
    """Centralize's cve_severity CHECK constraint only allows critical/high/
    medium/low. Vnotice also has "Informational" and sometimes NULL -- map
    anything outside the four allowed values to NULL rather than guessing,
    since a CHECK violation would reject the whole insert.
    """
    sev = (vnotice_severity or "").strip().lower()
    return sev if sev in _CENTRALIZE_SEVERITIES else None


def fetch_vnotice_cves(api_base: str = VNOTICE_API_BASE, timeout: float = 30.0) -> list[dict]:
    """Pull Vnotice's current CVE set. Vnotice already enforces a 30-day
    retention window, so one unfiltered call is the whole relevant corpus --
    no need to page or date-filter here too."""
    resp = httpx.get(f"{api_base.rstrip('/')}/cves/", params={"limit": 20000},
                     timeout=timeout, verify=False)
    resp.raise_for_status()
    return resp.json()


def fetch_centralize_products(engine) -> list[dict]:
    """Only the columns role_vnotice was actually granted -- asking for more
    would just fail, which is the point."""
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT product_id, vendor, product_name, software_version, product_category "
            "FROM product"
        )).mappings().all()
    return [dict(r) for r in rows]


def fetch_existing_finding_keys(engine) -> set[tuple[int, str]]:
    """(product_id, cve_id) pairs already recorded, so re-running this script
    never creates duplicate findings or disturbs a human's triage of one that
    already exists (status is never touched by this script on an existing row)."""
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT product_id, cve_id FROM vulnerability_finding")).all()
    return {(r[0], r[1]) for r in rows}


def build_findings(cves: list[dict], products: list[dict],
                   existing: set[tuple[int, str]]) -> list[dict]:
    """Group Vnotice's CVEs by normalized vendor, then for each Centralize
    product emit one new-finding row per CVE under its normalized vendor --
    vendor-level matching only (see module docstring for why)."""
    by_vendor: dict[str, list[dict]] = {}
    for cve in cves:
        norm = _normalize(cve.get("vendor"))
        if norm in _NON_VENDOR_PLACEHOLDERS:
            continue
        by_vendor.setdefault(norm, []).append(cve)

    findings = []
    for product in products:
        norm = _normalize(product.get("vendor"))
        if norm in _NON_VENDOR_PLACEHOLDERS:
            continue
        for cve in by_vendor.get(norm, []):
            key = (product["product_id"], cve["cve_id"])
            if key in existing:
                continue
            pub = cve.get("published_date")
            detected_date = pub[:10] if pub else None
            findings.append({
                "product_id": product["product_id"],
                "cve_id": cve["cve_id"],
                "cve_severity": _map_severity(cve.get("severity")),
                "detected_date": detected_date,
                "status": "open",
                "notes": (
                    f"Auto-matched by Vnotice on vendor \"{cve.get('vendor')}\" "
                    f"(normalized: {norm}) against {product.get('product_name')} "
                    f"{product.get('software_version') or ''}. Vendor-level match "
                    "only -- product model and software version not verified "
                    "against the advisory text. Confirm applicability before acting."
                ).strip(),
            })
            existing.add(key)  # guard against the same pair appearing twice this run
    return findings


def insert_findings(engine, findings: list[dict]) -> int:
    if not findings:
        return 0
    with engine.begin() as conn:
        for f in findings:
            conn.execute(text(
                "INSERT INTO vulnerability_finding "
                "(product_id, cve_id, cve_severity, detected_date, status, notes) "
                "VALUES (:product_id, :cve_id, :cve_severity, :detected_date, :status, :notes)"
            ), f)
    return len(findings)


def sync(api_base: Optional[str] = None, database_url: Optional[str] = None) -> dict:
    db_url = database_url or CENTRALIZE_DATABASE_URL
    if not db_url:
        raise RuntimeError(
            "CENTRALIZE_DATABASE_URL is not configured -- set it to role_vnotice's "
            "own connection string (see sql/vnotice_role_setup.sql in the Centralize repo)."
        )
    engine = create_engine(db_url)

    cves = fetch_vnotice_cves(api_base or VNOTICE_API_BASE)
    products = fetch_centralize_products(engine)
    existing = fetch_existing_finding_keys(engine)

    findings = build_findings(cves, products, existing)
    inserted = insert_findings(engine, findings)

    return {
        "cves_considered": len(cves),
        "products_checked": len(products),
        "findings_inserted": inserted,
    }


def main():
    ts = datetime.utcnow().isoformat()
    try:
        result = sync()
        print(f"[{ts}] centralize_sync OK: {result}")
    except Exception as e:
        print(f"[{ts}] centralize_sync ERR {e!r}")
        sys.exit(1)


if __name__ == "__main__":
    main()
