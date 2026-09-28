"""The only door between the database and the AI.

Everything that goes into an AI prompt must be read through ai_read_cve(), which
uses its own SQLite connection that is:

  * opened read-only at the file level (mode=ro) -- it cannot write, ever;
  * guarded by a SQLite authorizer that allows nothing but SELECTs reading the
    allowlisted columns of the vulnerability tables (`cves`, `cve_insights`) in
    AI_READABLE. users, user_configs
    (SMTP passwords, webhook URLs, bot tokens), notification_triggers, app_state
    and every other column are denied by the database engine itself, not by
    convention -- a future change that tries to pull them into a prompt through
    this connection fails with an error instead of leaking them.

The AI itself has no tools and no connection of its own: it only ever sees the
text the backend builds from what this module returns (plus the public CVE.org
record for the same CVE).

Fails closed: if DATABASE_URL isn't SQLite, the authorizer can't be applied, so
AI reads are refused rather than done without the guard.
"""
import sqlite3
from typing import Optional
from pathlib import Path

from sqlalchemy.engine import make_url

from database import DATABASE_URL

AI_READABLE = {
    "cves": frozenset({"cve_id", "title", "description", "severity", "cvss_score", "vendor", "product"}),
    "cve_insights": frozenset({"cve_id", "affected_versions", "affected_conditions", "mitigation",
                               "remediation", "fixed_versions", "iocs"}),
}


class AIAccessError(Exception):
    pass


def _authorizer(action, arg1, arg2, dbname, source):
    if action == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_READ:   # arg1 = table, arg2 = column
        if arg2 in AI_READABLE.get(arg1, ()):
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_DENY          # writes, pragmas, attach, other tables: all denied


def _connect():
    url = make_url(DATABASE_URL)
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        raise AIAccessError("AI access is only enabled on the SQLite database, where the "
                            "read-only table/column guard can be enforced.")
    path = Path(url.database).resolve()
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    conn.set_authorizer(_authorizer)
    return conn


def ai_read_cve(cve_id: str, columns, table: str = "cves") -> Optional[dict]:
    """One CVE's allowed columns from `table`, read through the guarded connection."""
    cols = list(columns)
    bad = [c for c in cols if c not in AI_READABLE.get(table, ())]
    if bad:
        raise AIAccessError(f"columns not readable by the AI in {table}: {bad}")
    conn = _connect()
    try:
        row = conn.execute(f"SELECT {', '.join(cols)} FROM {table} WHERE cve_id = ? LIMIT 1", (cve_id,)).fetchone()
    finally:
        conn.close()
    return dict(zip(cols, row)) if row else None
