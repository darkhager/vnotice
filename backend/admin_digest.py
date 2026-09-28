"""Admin summary: every 10 minutes (vnotice-admin-digest.timer), post ONE Teams
card to the admin webhook(s) listing every CVE added since the last summary,
across every feed. Skipped when nothing is new, so it never posts empty cards.

Individual users keep their per-CVE alerts (main._evaluate_triggers); this is the
all-feeds overview for the admin channel, which per-CVE posting would flood
(~430 new CVEs/day, mostly NVD).

Webhook URLs are secrets (anyone holding one can post to the channel), so they
are stored Fernet-encrypted in backend/secrets.json next to the AI key. The
"last summary" watermark lives in app_state and only advances once every
webhook has accepted the post, so a failed post is retried next run.

Run by hand:  python admin_digest.py          (post if anything is new)
              python admin_digest.py --test   (post a small test card)
"""
import json
import logging
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta

import crypto
import models
from database import SessionLocal
from llm import _lock, _read, _write   # ponytail: reuse the same encrypted secrets.json store

logger = logging.getLogger("vnotice.admin_digest")

STATE_KEY = "admin_digest_state"
DASHBOARD_URL = "http://10.4.150.57:4000"
MAX_LISTED = 40          # a Teams card has a ~28KB limit; the rest are counted, not listed
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


# ─── settings (webhooks never leave the server in the clear) ───

def _webhooks():
    enc = _read().get("admin_digest", {}).get("webhooks_enc", [])
    urls = [crypto.decrypt(u) for u in enc]
    return [u for u in urls if u and not u.startswith("enc::")]


def public_settings():
    urls = _webhooks()
    return {"enabled": bool(_read().get("admin_digest", {}).get("enabled")) and bool(urls),
            "webhooks": ["…" + u[-6:] for u in urls]}


def save(webhooks, enabled):
    with _lock:
        data = _read()
        data["admin_digest"] = {"enabled": bool(enabled),
                                "webhooks_enc": [crypto.encrypt(u.strip()) for u in webhooks if u.strip()]}
        _write(data)


# ─── posting ───

def _post(url, card):
    body = json.dumps({"type": "message", "attachments": [
        {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]}).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        if resp.status not in (200, 201, 202):
            raise RuntimeError(f"HTTP {resp.status}")


def _card(cves, since, until):
    by_source = {}
    for c in cves:
        by_source[c.rss_source or "Other"] = by_source.get(c.rss_source or "Other", 0) + 1
    seen, unique = set(), []
    for c in sorted(cves, key=lambda c: (-_SEV_RANK.get((c.severity or "").lower(), 0), -(float(c.cvss_score or 0)))):
        if c.cve_id not in seen:
            seen.add(c.cve_id)
            unique.append(c)
    crit = sum(1 for c in unique if (c.severity or "").lower() == "critical")
    high = sum(1 for c in unique if (c.severity or "").lower() == "high")
    body = [
        {"type": "TextBlock", "size": "medium", "weight": "bolder", "wrap": True,
         "text": f"📋 Vnotice summary — {len(unique)} new CVE{'s' if len(unique) != 1 else ''}"},
        {"type": "TextBlock", "isSubtle": True, "spacing": "none", "wrap": True,
         "text": f"{since:%Y-%m-%d %H:%M} → {until:%H:%M} UTC · Critical {crit} · High {high}"},
        {"type": "TextBlock", "wrap": True, "size": "small",
         "text": " · ".join(f"{s}: {n}" for s, n in sorted(by_source.items(), key=lambda x: -x[1]))},
    ]
    for c in unique[:MAX_LISTED]:
        cvss = f"{float(c.cvss_score):.1f}" if c.cvss_score is not None else "N/A"
        title = (c.title or "").replace("\n", " ")
        title = title[:90] + ("…" if len(title) > 90 else "")
        body.append({"type": "TextBlock", "wrap": True, "size": "small", "spacing": "small",
                     "text": f"**{c.cve_id}** · {(c.severity or 'N/A').upper()} {cvss} · {c.product or c.vendor or ''} — {title}"})
    if len(unique) > MAX_LISTED:
        body.append({"type": "TextBlock", "wrap": True, "isSubtle": True,
                     "text": f"+{len(unique) - MAX_LISTED} more (lower severity) — see the dashboard."})
    return {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
            "version": "1.4", "body": body,
            "actions": [{"type": "Action.OpenUrl", "title": "Open Vnotice", "url": DASHBOARD_URL}]}


def run(test=False):
    cfg = _read().get("admin_digest", {})
    urls = _webhooks()
    if not urls or not (cfg.get("enabled") or test):
        return "admin digest off (no enabled webhook)"
    if test:
        card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                "version": "1.4", "body": [{"type": "TextBlock", "wrap": True, "weight": "bolder",
                                            "text": "✅ Vnotice admin summary — test. Summaries will arrive here every 10 minutes when new CVEs come in."}]}
        for u in urls:
            _post(u, card)
        return f"test card posted to {len(urls)} webhook(s)"

    db = SessionLocal()
    try:
        row = db.query(models.AppState).filter(models.AppState.key == STATE_KEY).first()
        now = datetime.utcnow()
        since = datetime.fromisoformat(row.value["since"]) if row and row.value and row.value.get("since") \
            else now - timedelta(minutes=10)
        cves = db.query(models.CVE).filter(models.CVE.created_at > since).all()
        if not cves:
            return "nothing new"
        until = max(c.created_at for c in cves)
        card = _card(cves, since, until)
        failed = 0
        for u in urls:
            try:
                _post(u, card)
            except (urllib.error.URLError, OSError, RuntimeError) as e:
                failed += 1
                logger.error(f"admin digest post failed: {e!r}")
        if failed:
            return f"{failed}/{len(urls)} webhook(s) failed; will retry next run"
        value = {"since": until.isoformat(), "last_posted": now.isoformat(), "last_count": len(cves)}
        if row:
            row.value = value
        else:
            db.add(models.AppState(key=STATE_KEY, value=value))
        db.commit()
        return f"posted summary of {len(cves)} CVE row(s) to {len(urls)} webhook(s)"
    finally:
        db.close()


if __name__ == "__main__":
    print(f"[{datetime.utcnow().isoformat()}] {run(test='--test' in sys.argv)}")
