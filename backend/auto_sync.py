"""Scheduled server-side feed refresh (run by the vnotice-autosync systemd timer).

The web UI cannot trigger /sync/ — it sends no auth token, so the request 401s.
This job mints a short-lived JWT for a dedicated low-privilege service account and
calls the local /sync/ endpoint, which runs the full real ingestion pipeline
(per-feed routing, dedup, real EPSS from FIRST.org, keyword extraction). Run with
WorkingDirectory=backend so load_dotenv() picks up the same SECRET_KEY as the
running backend, otherwise the token would be rejected.
"""
import os
import sys
import json
import uuid
import datetime
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database import SessionLocal
import models
import auth

API = os.getenv("VNOTICE_API", "http://127.0.0.1:8080")
SVC_EMAIL = "auto-sync@vnotice.local"

FEEDS = [
    {"name": "NVD / NIST CVE", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "active": True},
    {"name": "Splunk Security Advisories", "url": "https://advisory.splunk.com/advisories", "active": True},
    {"name": "Check Point Advisories", "url": "https://support.checkpoint.com/security-advisories", "active": True},
    {"name": "Palo Alto Networks", "url": "https://security.paloaltonetworks.com/rss.xml", "active": True},
    {"name": "Fortinet PSIRT", "url": "https://fortiguard.com/rss/ir.xml", "active": True},
    {"name": "Ubuntu Security", "url": "https://ubuntu.com/security/notices/rss.xml", "active": True},
    {"name": "CERT.PL Security", "url": "https://cert.pl/en/rss.xml", "active": True},
    {"name": "Red Hat (RHEL)", "url": "https://access.redhat.com/hydra/rest/securitydata/cve.json", "active": True},
    {"name": "Rocky Linux", "url": "https://apollo.build.resf.org/api/v3/advisories/", "active": True},
    {"name": "Microsoft (Windows)", "url": "https://api.msrc.microsoft.com/cvrf/v3.0/updates", "active": True},
]


def _ensure_service_user(db):
    u = db.query(models.User).filter(models.User.email == SVC_EMAIL).first()
    if not u:
        u = models.User(id=uuid.uuid4(), email=SVC_EMAIL, username="auto-sync",
                        password_hash=auth.get_password_hash(uuid.uuid4().hex), role="user")
        db.add(u)
        db.commit()
    return u


def main():
    db = SessionLocal()
    _ensure_service_user(db)
    token = auth.create_access_token({"sub": SVC_EMAIL}, datetime.timedelta(minutes=15))
    body = json.dumps({"feeds": FEEDS, "scrapers": []}).encode()
    req = urllib.request.Request(
        f"{API}/sync/", data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    ts = datetime.datetime.utcnow().isoformat()
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            print(f"[{ts}] sync {r.status}: {r.read().decode()[:300]}")
    except urllib.error.HTTPError as e:
        print(f"[{ts}] sync HTTPERR {e.code}: {e.read().decode()[:300]}")
    except Exception as e:
        print(f"[{ts}] sync ERR {e!r}")


if __name__ == "__main__":
    main()
