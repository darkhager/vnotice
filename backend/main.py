from fastapi import FastAPI, Depends, HTTPException, status, Query, BackgroundTasks, Body
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import List, Optional
from datetime import timedelta, datetime
import random
import uuid
import re
import json
import asyncio
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import httpx

import logging

import models
import schemas
import auth
import source_store
import resource_monitor
from database import get_db, engine, SessionLocal
from rss_parser import RSSIngestionService

logger = logging.getLogger("vnotice")

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

# Create all tables on startup
models.Base.metadata.create_all(bind=engine)

# ponytail: lightweight additive migration — create_all() won't ALTER existing
# tables, so add the keywords column to a pre-existing cves table if missing.
def _ensure_columns():
    try:
        with engine.begin() as conn:
            try:
                conn.exec_driver_sql("ALTER TABLE cves ADD COLUMN keywords TEXT")
            except Exception:
                pass  # column already exists
    except Exception as e:
        logger.warning(f"keywords column migration skipped: {e}")

_ensure_columns()

# Fail-safe: if the DB is empty but per-source files exist, rebuild the DB from
# them (e.g. after a lost/corrupt cvedb.sqlite). Files are the durable copy.
def _rebuild_db_from_files_if_empty():
    db = SessionLocal()
    try:
        if db.query(models.CVE).count() > 0:
            return
        records = source_store.read_all()
        for rec in records:
            db.add(models.CVE(**source_store.record_to_cve_kwargs(rec)))
        if records:
            db.commit()
            logger.warning(f"Rebuilt {len(records)} CVEs from source files (DB was empty)")
    except Exception as exc:
        db.rollback()
        logger.error(f"DB rebuild-from-files skipped: {exc}")
    finally:
        db.close()

_rebuild_db_from_files_if_empty()

app = FastAPI(title="CVE Monitoring API", version="1.0.0")

import os

# CORS — allow any origin so the app works on any IP (DHCP/LAN).
# Bearer-token auth doesn't need credentials mode, so allow_credentials stays False.
_raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
_allow_origins = ["*"] if _raw_origins.strip() == "*" else [o.strip() for o in _raw_origins.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allow_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────
# Auth
# ─────────────────────────────────────────

@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# ─────────────────────────────────────────
# Users
# ─────────────────────────────────────────

@app.post("/users/", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = auth.get_password_hash(user.password)
    new_user = models.User(
        email=user.email,
        username=user.username,
        password_hash=hashed_password
    )
    db.add(new_user)
    db.flush()  # get new_user.id before commit

    # Auto-create a default UserConfig for the new user
    default_config = models.UserConfig(user_id=new_user.id)
    db.add(default_config)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.get("/users/me", response_model=schemas.UserResponse)
def read_users_me(current_user: models.User = Depends(auth.get_current_user)):
    return current_user


@app.put("/users/me", response_model=schemas.UserResponse)
def update_user_me(
    username: Optional[str] = None,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db)
):
    if username is not None:
        current_user.username = username
    current_user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(current_user)
    return current_user


# ─────────────────────────────────────────
# User Config
# ─────────────────────────────────────────

def _get_or_create_config(user: models.User, db: Session) -> models.UserConfig:
    """Get the user's config, creating a default one if it doesn't exist."""
    cfg = db.query(models.UserConfig).filter(models.UserConfig.user_id == user.id).first()
    if not cfg:
        cfg = models.UserConfig(user_id=user.id)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


@app.get("/users/me/config", response_model=schemas.UserConfigResponse)
def get_my_config(
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db)
):
    return _get_or_create_config(current_user, db)


@app.put("/users/me/config", response_model=schemas.UserConfigResponse)
def update_my_config(
    config_update: schemas.UserConfigUpdate,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db)
):
    cfg = _get_or_create_config(current_user, db)
    update_data = config_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(cfg, field, value)
    cfg.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(cfg)
    return cfg


# ─────────────────────────────────────────
# CVEs
# ─────────────────────────────────────────

@app.get("/cves/", response_model=List[schemas.CVEResponse])
def get_cves(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=1000),
    severity: Optional[List[str]] = Query(None),
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    try:
        query = db.query(models.CVE)

        if severity:
            if "all" not in [s.lower() for s in severity]:
                from sqlalchemy import or_
                conditions = [models.CVE.severity.ilike(s) for s in severity]
                query = query.filter(or_(*conditions))
        if vendor:
            query = query.filter(models.CVE.vendor.ilike(f"%{vendor}%"))
        if product:
            query = query.filter(models.CVE.product.ilike(f"%{product}%"))
        if search:
            query = query.filter(
                models.CVE.title.ilike(f"%{search}%") |
                models.CVE.description.ilike(f"%{search}%")
            )

        return query.order_by(models.CVE.published_date.desc()).offset(skip).limit(limit).all()
    except Exception as exc:
        # Fail-safe: DB unavailable — serve from per-source files (degraded filtering).
        logger.error(f"/cves/ DB query failed, serving from source files: {exc}")
        return source_store.query_fallback(
            severity=severity, vendor=vendor, product=product,
            search=search, skip=skip, limit=limit,
        )


@app.get("/cves/{cve_id}", response_model=schemas.CVEResponse)
def get_cve(cve_id: str, db: Session = Depends(get_db)):
    cve = db.query(models.CVE).filter(models.CVE.cve_id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve


# ─────────────────────────────────────────
# Sync
# ─────────────────────────────────────────

def _infer_vendor_product(feed_name: str, title: str):
    """Infer vendor and product from the feed name and CVE title."""
    fn = (feed_name or "").lower()
    t  = (title    or "").lower()

    # Source-name matches — most reliable
    if "fortinet" in fn or "fortiguard" in fn:
        return "Fortinet", "FortiOS"
    if "palo alto" in fn:
        return "Palo Alto Networks", "PAN-OS"
    if "cisco" in fn:
        return "Cisco", "IOS/NX-OS"
    if "f5" in fn:
        return "F5 Networks", "BIG-IP"
    if "splunk" in fn:
        return "Splunk", "Splunk Enterprise"
    if "check point" in fn or "checkpoint" in fn:
        return "Check Point", "Security Gateway"
    if "microsoft" in fn:
        return "Microsoft", "Windows"
    if "vmware" in fn or "broadcom" in fn:
        return "VMware", "vSphere"
    if "juniper" in fn:
        return "Juniper Networks", "JunOS"
    if "ivanti" in fn:
        return "Ivanti", "Connect Secure"
    if "ubuntu" in fn:
        if "openssl" in t or "libssl" in t:      return "Ubuntu", "OpenSSL"
        if "nginx" in t:                         return "Ubuntu", "nginx"
        if "php" in t:                           return "Ubuntu", "PHP"
        if "apache" in t:                        return "Ubuntu", "Apache"
        if "mysql" in t or "mariadb" in t:       return "Ubuntu", "MySQL/MariaDB"
        if "curl" in t:                          return "Ubuntu", "curl"
        if "samba" in t:                         return "Ubuntu", "Samba"
        if "python" in t:                        return "Ubuntu", "Python"
        return "Ubuntu", "Linux Kernel"
    if "zero day" in fn or "zdi" in fn:
        if "microsoft" in t or "windows" in t:   return "Microsoft", "Windows"
        if "adobe" in t:                          return "Adobe", "Acrobat/Reader"
        if "apple" in t or "safari" in t:         return "Apple", "macOS/iOS"
        if "google" in t or "chrome" in t:        return "Google", "Chrome"

    # Title-based vendor detection
    if "fortios" in t or ("fortinet" in t and "fortigate" in t):
        return "Fortinet", "FortiOS"
    if "pan-os" in t or "globalprotect" in t:
        return "Palo Alto Networks", "PAN-OS"
    if "cisco ios" in t or "cisco nx" in t or "cisco asa" in t:
        return "Cisco", "IOS/NX-OS"
    if "windows" in t and ("microsoft" in t or "ms" in t):
        return "Microsoft", "Windows"
    if "linux kernel" in t or ("linux" in t and "kernel" in t):
        return "Linux", "Linux Kernel"
    if "apache" in t and ("http" in t or "tomcat" in t or "struts" in t):
        return "Apache", "HTTP Server"
    if "vmware" in t:
        return "VMware", "vSphere"
    if "big-ip" in t:
        return "F5 Networks", "BIG-IP"
    if "xz utils" in t or "liblzma" in t:
        return "XZ Utils", "XZ Utils"
    if "runc" in t or "containerd" in t:
        return "Docker", "runc"
    if "spring" in t and ("framework" in t or "boot" in t):
        return "VMware", "Spring Framework"
    if "openssh" in t:                               return "OpenBSD", "OpenSSH"
    if "openssl" in t or "libssl" in t:              return "OpenSSL", "OpenSSL"
    if "nginx" in t:                                 return "nginx", "nginx"
    if "wordpress" in t:                             return "WordPress", "WordPress"
    if "gitlab" in t:                                return "GitLab", "GitLab CE/EE"
    if "jenkins" in t:                               return "Jenkins", "Jenkins"
    if "kubernetes" in t:                            return "CNCF", "Kubernetes"
    if "redis" in t:                                 return "Redis", "Redis"
    if "mysql" in t:                                 return "Oracle", "MySQL"
    if "mariadb" in t:                               return "MariaDB", "MariaDB"
    if "postgresql" in t or "postgres" in t:         return "PostgreSQL", "PostgreSQL"
    if "php" in t:                                   return "PHP Group", "PHP"
    if "chrome" in t or "chromium" in t:             return "Google", "Chrome"
    if "firefox" in t:                               return "Mozilla", "Firefox"
    if "safari" in t and "apple" in t:               return "Apple", "Safari"
    if "exim" in t:                                  return "Exim", "Exim MTA"
    if "samba" in t:                                 return "Samba", "Samba"
    if "log4j" in t or "log4shell" in t:             return "Apache", "Log4j"
    if "struts" in t:                                return "Apache", "Struts"
    if "tomcat" in t:                                return "Apache", "Tomcat"
    if "elasticsearch" in t or "opensearch" in t:    return "Elastic", "Elasticsearch"
    if "mongodb" in t:                               return "MongoDB", "MongoDB"
    if "grafana" in t:                               return "Grafana Labs", "Grafana"
    if "citrix" in t or "netscaler" in t:            return "Citrix", "Citrix ADC"
    if "zimbra" in t:                                return "Zimbra", "Zimbra"
    if "exchange" in t and "server" in t:            return "Microsoft", "Exchange Server"
    if "sharepoint" in t:                            return "Microsoft", "SharePoint"
    if "winrar" in t:                                return "RARLAB", "WinRAR"
    if "drupal" in t:                                return "Drupal", "Drupal CMS"
    if "grafana" in t:                               return "Grafana Labs", "Grafana"
    return "Various", "Various"


async def _evaluate_triggers(user_id: str, db_url: str = ""):
    """After a sync, check if any new CVEs match the user's notification triggers
    and fire alerts on the configured channels. Runs as a background task."""
    import logging as _log
    _logger = _log.getLogger(__name__)
    db = SessionLocal()
    try:
        cfg = db.query(models.UserConfig).filter(models.UserConfig.user_id == user_id).first()
        triggers = db.query(models.NotificationTrigger).filter(
            models.NotificationTrigger.user_id == user_id
        ).all()
        if not triggers or not cfg:
            return

        # Only look at CVEs added in the last 10 minutes
        recent_cutoff = datetime.utcnow() - timedelta(minutes=10)
        recent_cves = db.query(models.CVE).filter(
            models.CVE.created_at >= recent_cutoff
        ).all()

        for cve in recent_cves:
            for trigger in triggers:
                matched = True
                if trigger.keyword and trigger.keyword.lower() not in (
                    (cve.title or "") + " " + (cve.description or "")
                ).lower():
                    matched = False
                if trigger.vendor and trigger.vendor.lower() not in (cve.vendor or "").lower():
                    matched = False
                if trigger.product and trigger.product.lower() not in (cve.product or "").lower():
                    matched = False
                if trigger.min_severity:
                    if _SEVERITY_ORDER.get((cve.severity or "").lower(), 0) < \
                       _SEVERITY_ORDER.get(trigger.min_severity.lower(), 0):
                        matched = False
                if trigger.min_cvss_score is not None:
                    if (cve.cvss_score or 0) < float(trigger.min_cvss_score):
                        matched = False
                if not matched:
                    continue

                # Fire on every enabled channel
                alert_kwargs = dict(
                    title=cve.title or cve.cve_id,
                    severity=cve.severity or "Medium",
                    cve_id=cve.cve_id,
                    description=(cve.description or "")[:300],
                    reference_url=cve.reference_url,
                )
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        if cfg.notify_teams and cfg.teams_webhook:
                            payload = _build_teams_card(**alert_kwargs)
                            await client.post(cfg.teams_webhook, json=payload)
                        if cfg.notify_discord and cfg.discord_webhook:
                            payload = _build_discord_payload(**alert_kwargs)
                            await client.post(cfg.discord_webhook, json=payload)
                        if cfg.notify_telegram and cfg.telegram_bot_token and cfg.telegram_chat_id:
                            text_body = _build_telegram_text(**alert_kwargs)
                            await client.post(
                                f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendMessage",
                                json={"chat_id": cfg.telegram_chat_id, "text": text_body, "parse_mode": "HTML"},
                            )
                        if (cfg.notify_email and cfg.smtp_host and cfg.smtp_username
                                and cfg.smtp_password and cfg.smtp_to_address):
                            sev = (cve.severity or "Medium").upper()
                            ref = cve.reference_url or ""
                            desc = (cve.description or "")[:300]
                            subject = f"[Vnotice Alert] {cve.cve_id} — {sev}"
                            body = (
                                '<html><body style="font-family:sans-serif">'
                                f'<h2 style="color:#c0392b">🚨 CVE Alert: {cve.cve_id}</h2><table>'
                                f'<tr><td><b>Title</b></td><td>{cve.title or cve.cve_id}</td></tr>'
                                f'<tr><td><b>Severity</b></td><td>{sev}</td></tr>'
                                + (f'<tr><td><b>Description</b></td><td>{desc}</td></tr>' if desc else '')
                                + (f'<tr><td><b>Reference</b></td><td><a href="{ref}">{ref}</a></td></tr>' if ref else '')
                                + '</table></body></html>'
                            )
                            # _send_smtp is blocking — run it off the event loop.
                            await asyncio.get_event_loop().run_in_executor(
                                None, _send_smtp, cfg.smtp_host, cfg.smtp_port or 587,
                                cfg.smtp_username, cfg.smtp_password, cfg.smtp_to_address,
                                subject, body,
                            )
                except Exception as exc:
                    _logger.error(f"Trigger alert failed for {cve.cve_id}: {exc}")
    finally:
        db.close()


@app.post("/sync/", response_model=schemas.SyncResponse)
def sync_threat_sources(
    sync_req: schemas.SyncRequest,
    background_tasks: BackgroundTasks,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    feeds_checked = 0
    scrapers_checked = 0
    new_cves_added = 0
    two_years_ago = datetime.utcnow() - timedelta(days=730)

    # Preload existing keys once. Previously each parsed CVE triggered its own
    # SELECT (N+1 — hundreds of round-trips per sync); now it's a single query
    # plus O(1) set lookups, which also dedupes within this batch.
    existing_pairs = {(cid, src) for cid, src in db.query(models.CVE.cve_id, models.CVE.rss_source).all()}
    existing_ids = {cid for cid, _ in existing_pairs}

    # Records to persist to the per-source fail-safe files. Deterministic sources
    # write their full parsed set; random sources (generic RSS / scrapers) record
    # only newly-built rows so files stay consistent with what the DB stored.
    synced_by_source = {}

    def _insert_items(items, source_name):
        """Insert parsed CVE dicts (rich shape) not already stored for this source."""
        nonlocal new_cves_added
        if items:
            synced_by_source.setdefault(source_name, []).extend(items)
        for item in items:
            key = (item["cve_id"], source_name)
            if key in existing_pairs:
                continue
            item["keywords"] = RSSIngestionService.extract_keywords(
                item.get("title", ""), item.get("description", ""),
                item.get("vendor", ""), item.get("product", ""))
            db.add(models.CVE(
                cve_id=item["cve_id"],
                title=item["title"],
                description=item["description"],
                severity=item["severity"],
                cvss_score=item["cvss_score"],
                epss=item["epss"],
                published_date=item["published_date"],
                updated_date=item["published_date"],
                vendor=item["vendor"],
                product=item["product"],
                reference_url=item["reference_url"],
                rss_source=source_name,
                keywords=item["keywords"],
            ))
            existing_pairs.add(key)
            existing_ids.add(item["cve_id"])
            new_cves_added += 1

    for feed in sync_req.feeds:
        if not feed.active:
            continue
        feeds_checked += 1

        # Real-data sources (rich item shape) — routed by URL, deduped via _insert_items
        if "services.nvd.nist.gov" in feed.url:
            _insert_items(RSSIngestionService.fetch_nvd_api(), feed.name)
            continue
        if "advisory.splunk.com" in feed.url:
            _insert_items(RSSIngestionService.fetch_splunk_advisories(), feed.name)
            continue
        if "support.checkpoint.com" in feed.url:
            _insert_items(RSSIngestionService.fetch_checkpoint_advisories(), feed.name)
            continue
        if "security.paloaltonetworks.com" in feed.url:
            _insert_items(RSSIngestionService.fetch_paloalto_advisories(), feed.name)
            continue
        if "access.redhat.com" in feed.url:
            _insert_items(RSSIngestionService.fetch_redhat_advisories(), feed.name)
            continue
        if "resf.org" in feed.url or "rockylinux.org" in feed.url:
            _insert_items(RSSIngestionService.fetch_rocky_advisories(), feed.name)
            continue
        if "msrc.microsoft.com" in feed.url or "microsoft.com/cvrf" in feed.url:
            _insert_items(RSSIngestionService.fetch_microsoft_advisories(), feed.name)
            continue

        # Standard XML / RSS / Atom ingestion
        parsed_cves = RSSIngestionService.fetch_and_parse_rss(feed.url)
        for item in parsed_cves:
            # Skip items older than 2 years
            pub = item.get("published_date")
            if pub:
                pub_naive = pub.replace(tzinfo=None) if getattr(pub, "tzinfo", None) else pub
                if pub_naive < two_years_ago:
                    continue
            key = (item["cve_id"], feed.name)
            if key not in existing_pairs:
                vendor, product = _infer_vendor_product(feed.name, item["title"])
                record = {
                    "cve_id": item["cve_id"],
                    "title": item["title"],
                    "description": item["description"],
                    "severity": random.choice(["Medium", "High", "Critical"]),
                    "cvss_score": round(random.uniform(5.0, 9.8), 1),
                    "epss": round(random.uniform(0.01, 0.95), 4),
                    "published_date": item["published_date"],
                    "updated_date": item["published_date"],
                    "vendor": vendor,
                    "product": product,
                    "reference_url": item["reference_url"],
                    "keywords": RSSIngestionService.extract_keywords(
                        item["title"], item["description"], vendor, product),
                }
                db.add(models.CVE(**record, rss_source=feed.name))
                synced_by_source.setdefault(feed.name, []).append(record)
                existing_pairs.add(key)
                existing_ids.add(item["cve_id"])
                new_cves_added += 1

    for scraper in sync_req.scrapers:
        if not scraper.active:
            continue
        scrapers_checked += 1
        extracted_cves = RSSIngestionService.scrape_webpage_regex(scraper.url, scraper.regex)
        for cve_id in extracted_cves:
            if cve_id not in existing_ids:
                details = RSSIngestionService.generate_cve_details_for_id(cve_id, scraper.name, scraper.url)
                record = {k: details[k] for k in [
                    "cve_id", "title", "description", "severity", "cvss_score",
                    "epss", "published_date", "updated_date", "vendor",
                    "product", "reference_url",
                ]}
                record["keywords"] = RSSIngestionService.extract_keywords(
                    details["title"], details["description"],
                    details["vendor"], details["product"])
                db.add(models.CVE(**record, rss_source=details["rss_source"]))
                synced_by_source.setdefault(scraper.name, []).append(record)
                existing_ids.add(cve_id)
                existing_pairs.add((cve_id, scraper.name))
                new_cves_added += 1

    # Real EPSS from FIRST.org (batched) for everything ingested this sync.
    # A CVE the API doesn't know => None, surfaced as "N/A" (no more random values).
    pending_cves = [o for o in db.new if isinstance(o, models.CVE)]
    all_ids = {o.cve_id for o in pending_cves}
    for recs in synced_by_source.values():
        all_ids.update(r["cve_id"] for r in recs)
    if all_ids:
        epss_scores = RSSIngestionService.fetch_epss_batch(list(all_ids))
        for o in pending_cves:
            o.epss = epss_scores.get((o.cve_id or "").upper())
        for recs in synced_by_source.values():
            for r in recs:
                r["epss"] = epss_scores.get((r["cve_id"] or "").upper())

    # Fail-safe: write each source's CVEs to its per-source file BEFORE the DB
    # commit, so the durable copy survives even if the commit fails.
    for src, recs in synced_by_source.items():
        source_store.write_source(src, recs)

    # Persist feed/scraper config to UserConfig so other clients can load it
    cfg = _get_or_create_config(current_user, db)
    cfg.feeds_config = [f.model_dump() for f in sync_req.feeds]
    cfg.scrapers_config = [s.model_dump() for s in sync_req.scrapers]

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database transaction error: {e}")

    # Evaluate notification triggers against newly added CVEs (background, non-blocking)
    if new_cves_added > 0:
        background_tasks.add_task(_evaluate_triggers, str(current_user.id), str(engine.url))

    return schemas.SyncResponse(
        status="success",
        feeds_checked=feeds_checked,
        scrapers_checked=scrapers_checked,
        new_cves_added=new_cves_added,
        message=f"Sync completed. Checked {feeds_checked} RSS feeds & {scrapers_checked} scrapers. Added {new_cves_added} new CVEs."
    )


@app.delete("/cves/clear-checkpoint")
def clear_checkpoint_cves(
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    """Delete all CVEs ingested from Check Point sources."""
    from sqlalchemy import or_
    deleted = db.query(models.CVE).filter(
        or_(
            models.CVE.rss_source.ilike("%check point%"),
            models.CVE.vendor.ilike("%check point%"),
            models.CVE.vendor.ilike("%checkpoint%")
        )
    ).delete(synchronize_session=False)
    db.commit()
    return {"deleted": deleted, "message": f"Removed {deleted} Check Point CVE records."}


@app.get("/keywords/")
def list_keywords(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Aggregated keyword store — top extracted keywords across all CVEs with counts.

    Powers keyword discovery (e.g. picking alert keywords) from the terms the
    extraction algorithm pulled out of ingested feed data and product names.
    """
    counts = {}
    try:
        for (kw_json,) in db.query(models.CVE.keywords).all():
            if not kw_json:
                continue
            kws = kw_json if isinstance(kw_json, list) else json.loads(kw_json)
            for kw in kws:
                counts[kw] = counts.get(kw, 0) + 1
    except Exception as e:
        logger.error(f"keyword aggregation failed: {e}")
        return {"total": 0, "keywords": []}
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    return {"total": len(counts), "keywords": [{"keyword": k, "count": c} for k, c in top]}


@app.get("/appstate/{key}")
def get_app_state(key: str, db: Session = Depends(get_db)):
    """Return a stored frontend state bundle (e.g. the profiles/settings blob)."""
    row = db.query(models.AppState).filter(models.AppState.key == key).first()
    return {"key": key, "value": row.value if row else None}


@app.api_route("/appstate/{key}", methods=["PUT", "POST"])
def put_app_state(key: str, payload: dict = Body(...), db: Session = Depends(get_db)):
    """Upsert a frontend state bundle. POST is supported so the browser can use
    navigator.sendBeacon on tab close. Persisting profiles here keeps them in the
    DB (shared across browsers, captured by backups)."""
    value = payload.get("value") if isinstance(payload, dict) else payload
    row = db.query(models.AppState).filter(models.AppState.key == key).first()
    if row:
        row.value = value
        row.updated_at = datetime.utcnow()
    else:
        db.add(models.AppState(key=key, value=value))
    db.commit()
    return {"key": key, "ok": True}


@app.get("/")
def root():
    return {"message": "CVE Monitoring API v1.0"}


# ─────────────────────────────────────────
# Engine Health Check
# ─────────────────────────────────────────

import time as _time
_APP_START = _time.time()

def _vnotice_subprocesses() -> list:
    """Best-effort list of the OS processes that make up this deployment —
    backend (uvicorn) + frontend (Next.js) — so Engine Status shows every
    subprocess, not just the API process. ponytail: psutil cmdline match,
    scoped to the current user's own processes."""
    procs: list = []
    try:
        import psutil
        me = psutil.Process().username()
    except Exception:
        return procs
    for p in psutil.process_iter(["pid", "name", "cmdline", "status", "create_time", "username"]):
        try:
            if p.info.get("username") != me:
                continue
            cmd = " ".join(p.info.get("cmdline") or []).lower()
            name = (p.info.get("name") or "").lower()
            if "uvicorn" in cmd and "main:app" in cmd:
                role = "Backend API (uvicorn)"
            elif "next-server" in name or "next-server" in cmd or ("node" in name and "next" in cmd):
                role = "Frontend (Next.js)"
            else:
                continue
            procs.append({
                "role": role,
                "name": p.info.get("name"),
                "pid": p.info.get("pid"),
                "status": p.info.get("status"),
                "mem_mb": round(p.memory_info().rss / 1e6, 1),
                "threads": p.num_threads(),
                "uptime_seconds": round(_time.time() - (p.info.get("create_time") or _time.time())),
            })
        except Exception:
            continue
    procs.sort(key=lambda x: x["role"])
    return procs


@app.get("/health/")
def engine_health(db: Session = Depends(get_db)):
    """Return CPU, memory, disk usage, DB status, uptime, and subprocesses."""
    result: dict = {
        "api_version": "1.0.0",
        "uptime_seconds": round(_time.time() - _APP_START),
        "database": "unknown",
        "cpu_percent": None,
        "memory": None,
        "disk": None,
        "process": None,
    }

    # Database connectivity
    try:
        db.execute(text("SELECT 1"))
        result["database"] = "connected"
    except Exception as e:
        result["database"] = f"error: {e}"

    # System metrics via psutil
    try:
        import psutil, os
        result["cpu_percent"] = psutil.cpu_percent(interval=0.2)
        vm = psutil.virtual_memory()
        result["memory"] = {
            "total_gb": round(vm.total / 1e9, 2),
            "used_gb":  round(vm.used  / 1e9, 2),
            "percent":  vm.percent,
        }
        du = psutil.disk_usage("/")
        result["disk"] = {
            "total_gb": round(du.total / 1e9, 2),
            "used_gb":  round(du.used  / 1e9, 2),
            "percent":  du.percent,
        }
        proc = psutil.Process(os.getpid())
        result["process"] = {
            "pid":        proc.pid,
            "status":     proc.status(),
            "mem_mb":     round(proc.memory_info().rss / 1e6, 1),
            "cpu_percent": proc.cpu_percent(interval=0.1),
            "threads":    proc.num_threads(),
        }
    except ImportError:
        # psutil not installed — fall back to shutil for disk
        import shutil, os
        try:
            du = shutil.disk_usage("/")
            result["disk"] = {
                "total_gb": round(du.total / 1e9, 2),
                "used_gb":  round(du.used  / 1e9, 2),
                "percent":  round(du.used / du.total * 100, 1),
            }
        except Exception:
            pass
    except Exception as e:
        result["metrics_error"] = str(e)

    result["subprocesses"] = _vnotice_subprocesses()
    return result


@app.on_event("startup")
async def _start_resource_sampler():
    """Begin recording host CPU/mem/disk % once per hour (kept ~365 days)."""
    asyncio.create_task(resource_monitor.sampler_loop())


@app.get("/metrics/usage")
def resource_usage_history():
    """Hourly CPU/mem/disk % history for the resource-usage dashboard."""
    return {"interval_seconds": 3600, "samples": resource_monitor.load_history()}


@app.post("/cves/refresh-epss")
def refresh_epss(db: Session = Depends(get_db)):
    """Backfill REAL EPSS scores from FIRST.org for every stored CVE (batched).
    CVEs the API has no score for are set to None (displayed as N/A)."""
    rows = db.query(models.CVE).all()
    scores = RSSIngestionService.fetch_epss_batch([r.cve_id for r in rows])
    found = 0
    for r in rows:
        val = scores.get((r.cve_id or "").upper())
        r.epss = val
        if val is not None:
            found += 1
    db.commit()
    return {"total": len(rows), "with_epss": found, "na": len(rows) - found}


# ─────────────────────────────────────────
# Notifications — Microsoft Teams
# ─────────────────────────────────────────

# Accept every current Teams incoming-webhook host. Microsoft retired the
# classic O365 connector (*.webhook.office.com/webhookb2/...) and now issues
# Power Automate "Workflows" webhooks on *.logic.azure.com — so all three forms
# below are valid destinations and must pass validation.
_TEAMS_WEBHOOK_RE = re.compile(
    r"^https://("
    r"[a-zA-Z0-9\-]+\.webhook\.office\.com/webhookb2/"   # classic connector
    r"|outlook\.office\.com/webhook/"                      # legacy connector
    r"|[a-zA-Z0-9\-.]+\.logic\.azure\.com[:/]"             # Power Automate Workflows
    r"|[a-zA-Z0-9\-.]+\.powerplatform\.com[:/]"           # Power Automate (Power Platform)
    r").+",
    re.IGNORECASE,
)

def _validate_teams_webhook(url: str) -> None:
    if not _TEAMS_WEBHOOK_RE.match(url):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid Teams webhook URL. Expected: https://<tenant>.webhook.office.com/webhookb2/..."
        )

def _build_teams_card(title: str, severity: str, cve_id: str,
                      description: Optional[str], reference_url: Optional[str]) -> dict:
    # The Teams Workflow ("Post card when a webhook request is received") requires
    # an Adaptive Card wrapped in the attachments envelope below — a plain
    # {"text": ...} body is accepted at HTTP level (202) but the flow then fails
    # to post it. So we always send a proper Adaptive Card.
    color_map = {"critical": "attention", "high": "warning", "medium": "accent", "low": "good"}
    color = color_map.get((severity or "").lower(), "default")
    facts = [{"title": "Severity", "value": severity}, {"title": "CVE ID", "value": cve_id}]
    if reference_url:
        facts.append({"title": "Reference", "value": reference_url})
    body = [{"type": "TextBlock", "text": f"🚨 {title}", "weight": "bolder",
             "size": "medium", "color": color, "wrap": True}]
    if description:
        body.append({"type": "TextBlock", "text": description, "wrap": True, "isSubtle": True})
    body.append({"type": "FactSet", "facts": facts})
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": body,
            },
        }],
    }


@app.post("/notifications/teams", status_code=200)
async def send_teams_alert(req: schemas.TeamsAlertRequest):
    """Send a CVE alert to a Microsoft Teams channel via Incoming Webhook."""
    _validate_teams_webhook(req.webhook_url)
    payload = _build_teams_card(req.title, req.severity, req.cve_id,
                                req.description, req.reference_url)
    last_error = ""
    for attempt in range(1, 4):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(req.webhook_url, json=payload)
            # Classic connectors answer 200; Workflows HTTP triggers answer 202.
            if resp.status_code in (200, 201, 202):
                return {"status": "sent", "attempts": attempt}
            last_error = f"Teams returned HTTP {resp.status_code}: {resp.text[:200]}"
        except httpx.TimeoutException:
            last_error = f"Attempt {attempt}: request timed out"
        except httpx.RequestError as exc:
            last_error = f"Attempt {attempt}: network error — {exc}"
        if attempt < 3:
            await asyncio.sleep(0.5 * attempt)
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"Teams webhook failed after 3 attempts. Last error: {last_error}"
    )


@app.post("/notifications/test-teams", status_code=200)
async def test_teams_webhook(req: schemas.TeamsTestRequest):
    """Send a test alert to verify a Teams webhook URL is working."""
    _validate_teams_webhook(req.webhook_url)
    payload = _build_teams_card(
        title="CVE Monitor — Test Alert",
        severity="Low",
        cve_id="CVE-TEST-0000",
        description="This is a test notification from CVE Monitoring App. If you see this, your Teams webhook is configured correctly.",
        reference_url=None,
    )
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(req.webhook_url, json=payload)
        # Classic connectors answer 200; Workflows HTTP triggers answer 202.
        if resp.status_code in (200, 201, 202):
            return {"status": "ok", "message": "Test alert delivered successfully."}
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Teams returned HTTP {resp.status_code}: {resp.text[:200]}"
        )
    except httpx.TimeoutException:
        raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                            detail="Teams webhook request timed out (10s).")
    except httpx.RequestError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY,
                            detail=f"Network error reaching Teams webhook: {exc}")


# ─────────────────────────────────────────
# Notifications — Discord
# ─────────────────────────────────────────

_DISCORD_COLOR = {"critical": 15158332, "high": 16744272, "medium": 16776960, "low": 3394611}

def _build_discord_payload(title: str, severity: str, cve_id: str,
                           description: Optional[str], reference_url: Optional[str]) -> dict:
    color = _DISCORD_COLOR.get(severity.lower(), 9807270)
    embed: dict = {
        "title": f"[{cve_id}] {title}",
        "description": description or "No description provided.",
        "color": color,
        "fields": [{"name": "Severity", "value": severity.upper(), "inline": True}],
    }
    if reference_url:
        embed["url"] = reference_url
        embed["fields"].append({"name": "Reference", "value": reference_url, "inline": False})
    return {"embeds": [embed]}


@app.post("/notifications/discord", status_code=200)
async def send_discord_alert(
    req: schemas.DiscordAlertRequest,
    current_user: models.User = Depends(auth.get_current_user),
):
    if not req.webhook_url.startswith("https://discord.com/api/webhooks/"):
        raise HTTPException(status_code=422, detail="Invalid Discord webhook URL.")
    payload = _build_discord_payload(req.title, req.severity, req.cve_id, req.description, req.reference_url)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(req.webhook_url, json=payload)
        if resp.status_code in (200, 204):
            return {"status": "sent"}
        raise HTTPException(status_code=502, detail=f"Discord returned HTTP {resp.status_code}: {resp.text[:200]}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Discord webhook timed out.")
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Network error: {exc}")


@app.post("/notifications/test-discord", status_code=200)
async def test_discord_webhook(
    req: schemas.DiscordTestRequest,
):
    if not req.webhook_url.startswith("https://discord.com/api/webhooks/"):
        raise HTTPException(status_code=422, detail="Invalid Discord webhook URL.")
    payload = _build_discord_payload(
        "CVE Monitor — Test Alert", "Low", "CVE-TEST-0000",
        "Test notification from CVE Monitoring App. Discord is configured correctly.", None
    )
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(req.webhook_url, json=payload)
        if resp.status_code in (200, 204):
            return {"status": "ok", "message": "Test alert delivered to Discord."}
        raise HTTPException(status_code=502, detail=f"Discord returned HTTP {resp.status_code}: {resp.text[:200]}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Discord webhook timed out.")
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Network error: {exc}")


# ─────────────────────────────────────────
# Notifications — Telegram
# ─────────────────────────────────────────

def _build_telegram_text(title: str, severity: str, cve_id: str,
                          description: Optional[str], reference_url: Optional[str]) -> str:
    lines = [
        f"<b>🚨 [{cve_id}]</b> {title}",
        f"Severity: <b>{severity.upper()}</b>",
    ]
    if description:
        lines.append(f"\n{description[:300]}{'…' if len(description or '') > 300 else ''}")
    if reference_url:
        lines.append(f'\n<a href="{reference_url}">View on NVD</a>')
    return "\n".join(lines)


@app.post("/notifications/telegram", status_code=200)
async def send_telegram_alert(
    req: schemas.TelegramAlertRequest,
    current_user: models.User = Depends(auth.get_current_user),
):
    text_body = _build_telegram_text(req.title, req.severity, req.cve_id, req.description, req.reference_url)
    url = f"https://api.telegram.org/bot{req.bot_token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json={"chat_id": req.chat_id, "text": text_body, "parse_mode": "HTML"})
        data = resp.json()
        if resp.status_code == 200 and data.get("ok"):
            return {"status": "sent"}
        raise HTTPException(status_code=502, detail=f"Telegram error: {data.get('description', resp.text[:200])}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Telegram request timed out.")
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Network error: {exc}")


@app.post("/notifications/test-telegram", status_code=200)
async def test_telegram_bot(
    req: schemas.TelegramTestRequest,
):
    url = f"https://api.telegram.org/bot{req.bot_token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json={
                "chat_id": req.chat_id,
                "text": "✅ <b>CVE Monitor — Test Alert</b>\nTelegram notifications are configured correctly.",
                "parse_mode": "HTML",
            })
        data = resp.json()
        if resp.status_code == 200 and data.get("ok"):
            return {"status": "ok", "message": "Test message delivered to Telegram."}
        raise HTTPException(status_code=502, detail=f"Telegram error: {data.get('description', resp.text[:200])}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Telegram request timed out.")
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Network error: {exc}")


# ─────────────────────────────────────────
# Notifications — Email (SMTP)
# ─────────────────────────────────────────

def _smtp_auth_detail(exc: smtplib.SMTPAuthenticationError) -> str:
    """Surface the mail server's real rejection reason (e.g. Gmail's
    "Username and Password not accepted" → an App Password is required) instead
    of a generic message, so the operator can act on it."""
    reason = exc.smtp_error.decode("utf-8", "replace") if isinstance(exc.smtp_error, bytes) else str(exc.smtp_error)
    return f"SMTP authentication rejected by mail server ({exc.smtp_code}): {reason}"


def _send_smtp(host: str, port: int, username: str, password: str,
               to_address: str, subject: str, body_html: str) -> None:
    # Empty host makes smtplib skip connect() and later fail with the cryptic
    # "please run connect() first" — guard with a clear, actionable message.
    if not (host or "").strip():
        raise smtplib.SMTPException(
            "SMTP host is not configured. Set the mail server (host/username/password) "
            "in Settings → Email Alerts.")
    if not (username or "").strip() or not (to_address or "").strip():
        raise smtplib.SMTPException(
            "SMTP username and recipient address are required. Complete them in "
            "Settings → Email Alerts.")
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = username
    msg["To"] = to_address
    msg.attach(MIMEText(body_html, "html"))
    ctx = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as server:
            server.login(username, password)
            server.sendmail(username, to_address, msg.as_string())
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.login(username, password)
            server.sendmail(username, to_address, msg.as_string())


@app.post("/notifications/email", status_code=200)
async def send_email_alert(
    req: schemas.EmailAlertRequest,
    current_user: models.User = Depends(auth.get_current_user),
):
    subject = f"[Vnotice Alert] {req.cve_id} — {req.severity.upper()}"
    body = f"""
<html><body style="font-family:sans-serif">
<h2 style="color:#c0392b">🚨 CVE Alert: {req.cve_id}</h2>
<table><tr><td><b>Title</b></td><td>{req.title}</td></tr>
<tr><td><b>Severity</b></td><td>{req.severity.upper()}</td></tr>
{'<tr><td><b>Description</b></td><td>' + (req.description or '') + '</td></tr>' if req.description else ''}
{'<tr><td><b>Reference</b></td><td><a href="' + req.reference_url + '">' + req.reference_url + '</a></td></tr>' if req.reference_url else ''}
</table>
</body></html>"""
    try:
        await asyncio.get_event_loop().run_in_executor(
            None, _send_smtp, req.smtp_host, req.smtp_port,
            req.smtp_username, req.smtp_password, req.to_address, subject, body
        )
        return {"status": "sent"}
    except smtplib.SMTPAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=_smtp_auth_detail(exc))
    except smtplib.SMTPException as exc:
        raise HTTPException(status_code=502, detail=f"SMTP error: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Email delivery failed: {exc}")


@app.post("/notifications/test-email", status_code=200)
async def test_email_config(
    req: schemas.EmailTestRequest,
):
    if req.cve_id:
        # ponytail: a CVE was supplied → send the real alert body (per-alert "send latest match").
        sev = (req.severity or "Medium").upper()
        subject = f"[Vnotice Alert] {req.cve_id} — {sev}"
        body = (
            '<html><body style="font-family:sans-serif">'
            f'<h2 style="color:#c0392b">🚨 CVE Alert: {req.cve_id}</h2><table>'
            f'<tr><td><b>Title</b></td><td>{req.title or req.cve_id}</td></tr>'
            f'<tr><td><b>Severity</b></td><td>{sev}</td></tr>'
            + (f'<tr><td><b>Description</b></td><td>{req.description}</td></tr>' if req.description else '')
            + (f'<tr><td><b>Reference</b></td><td><a href="{req.reference_url}">{req.reference_url}</a></td></tr>' if req.reference_url else '')
            + '</table></body></html>'
        )
        ok_msg = f"Alert email for {req.cve_id} sent to {req.to_address}."
    else:
        subject = "[Vnotice] Test Notification"
        body = "<html><body><p>✅ <b>CVE Monitor — Test Alert</b><br>Email notifications are configured correctly.</p></body></html>"
        ok_msg = f"Test email sent to {req.to_address}."
    try:
        await asyncio.get_event_loop().run_in_executor(
            None, _send_smtp, req.smtp_host, req.smtp_port,
            req.smtp_username, req.smtp_password, req.to_address, subject, body
        )
        return {"status": "ok", "message": ok_msg}
    except smtplib.SMTPAuthenticationError as exc:
        raise HTTPException(status_code=401, detail=_smtp_auth_detail(exc))
    except smtplib.SMTPException as exc:
        raise HTTPException(status_code=502, detail=f"SMTP error: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Email delivery failed: {exc}")


# ─────────────────────────────────────────
# Notifications — SMS (Twilio)
# ─────────────────────────────────────────

def _sms_body(cve_id: str, severity: str, cvss: Optional[float] = None) -> str:
    score = f" CVSS {cvss}" if cvss else ""
    return f"[Vnotice] {cve_id} ({severity.upper()}{score}) — Check dashboard for details."[:160]


@app.post("/notifications/sms", status_code=200)
async def send_sms_alert(
    req: schemas.SmsAlertRequest,
    current_user: models.User = Depends(auth.get_current_user),
):
    url = f"https://api.twilio.com/2010-04-01/Accounts/{req.twilio_sid}/Messages.json"
    body = _sms_body(req.cve_id, req.severity)
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, data={"From": req.from_number, "To": req.to_number, "Body": body},
                                     auth=(req.twilio_sid, req.twilio_token))
        data = resp.json()
        if resp.status_code == 201:
            return {"status": "sent", "sid": data.get("sid")}
        raise HTTPException(status_code=502, detail=f"Twilio error: {data.get('message', resp.text[:200])}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Twilio request timed out.")
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Network error: {exc}")


@app.post("/notifications/test-sms", status_code=200)
async def test_sms_config(
    req: schemas.SmsTestRequest,
):
    url = f"https://api.twilio.com/2010-04-01/Accounts/{req.twilio_sid}/Messages.json"
    body = "[Vnotice] Test message — SMS notifications are configured correctly."
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, data={"From": req.from_number, "To": req.to_number, "Body": body},
                                     auth=(req.twilio_sid, req.twilio_token))
        data = resp.json()
        if resp.status_code == 201:
            return {"status": "ok", "message": f"Test SMS sent to {req.to_number}."}
        raise HTTPException(status_code=502, detail=f"Twilio error: {data.get('message', resp.text[:200])}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Twilio request timed out.")
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Network error: {exc}")


# ─────────────────────────────────────────
# Notification Triggers
# ─────────────────────────────────────────

@app.post("/triggers/", response_model=schemas.TriggerResponse, status_code=201)
def create_trigger(
    trigger: schemas.TriggerCreate,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    if not any([trigger.keyword, trigger.vendor, trigger.product,
                trigger.min_severity, trigger.min_cvss_score is not None]):
        raise HTTPException(status_code=422, detail="At least one trigger condition is required.")
    row = models.NotificationTrigger(
        user_id=current_user.id,
        keyword=trigger.keyword,
        vendor=trigger.vendor,
        product=trigger.product,
        min_severity=trigger.min_severity,
        min_cvss_score=trigger.min_cvss_score,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@app.get("/triggers/", response_model=List[schemas.TriggerResponse])
def list_triggers(
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    return db.query(models.NotificationTrigger).filter(
        models.NotificationTrigger.user_id == current_user.id
    ).order_by(models.NotificationTrigger.created_at.desc()).all()


@app.delete("/triggers/{trigger_id}", status_code=204)
def delete_trigger(
    trigger_id: str,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    row = db.query(models.NotificationTrigger).filter(
        models.NotificationTrigger.id == trigger_id,
        models.NotificationTrigger.user_id == current_user.id,
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Trigger not found.")
    db.delete(row)
    db.commit()
