from fastapi import FastAPI, Depends, HTTPException, status, Query, BackgroundTasks, Body, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import List, Optional
from datetime import timedelta, datetime, timezone
import uuid
import re
import json
import asyncio
import gzip
import threading
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import httpx
from pydantic import TypeAdapter

import logging

import models
import schemas
import auth
import source_store
import resource_monitor
from database import get_db, engine, SessionLocal
from rss_parser import RSSIngestionService
import llm
import ai_access
import admin_digest
import threat_summary

logger = logging.getLogger("vnotice")

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

# ponytail: short-TTL response cache for GET /cves/. The CVE table only changes
# on /sync/ (and epss refresh / checkpoint clear), so identical queries — the
# dashboard's default view shared across operators/auto-refresh — skip the DB
# read and the Pydantic serialization of thousands of rows. Cleared on writes.
_CVE_LIST_ADAPTER = TypeAdapter(List[schemas.CVEResponse])
_CVES_CACHE: dict = {}     # query-string -> (timestamp, body_bytes, gzipped_body_bytes)
# Every write that changes the list (sync, EPSS refresh, checkpoint clear) clears
# the cache explicitly, so the TTL is only a safety net -- long enough that 100
# users aren't forced into a rebuild every few seconds.
_CVES_TTL = 300.0
# One lock per query: on a miss, a single request rebuilds while the rest wait
# for its result. Without this, every user who hit the page right after a cache
# clear rebuilt the same ~9MB response at once -- load-tested: 20 simultaneous
# misses took 36-43s each (CPU-bound serialization queued behind the GIL).
_CVES_LOCKS: dict = {}

# ponytail: fixed-window rate limit, in-process dict -- fine since uvicorn runs
# as a single worker here (no --workers flag), so there's only one process's
# state to keep consistent. Guards /token and /users/ against unlimited
# password-guessing / mass-registration now that there's a real login UI.
_RATE_LIMIT_BUCKETS: dict = {}   # (bucket, client_ip) -> [timestamps]


def _enforce_rate_limit(request: Request, bucket: str, max_attempts: int, window_seconds: float):
    ip = request.client.host if request.client else "unknown"
    key = (bucket, ip)
    now = _time.time()
    hits = [t for t in _RATE_LIMIT_BUCKETS.get(key, []) if now - t < window_seconds]
    if len(hits) >= max_attempts:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many attempts. Try again in {int(window_seconds - (now - hits[0]))}s.",
        )
    hits.append(now)
    _RATE_LIMIT_BUCKETS[key] = hits

# Create all tables on startup
models.Base.metadata.create_all(bind=engine)

# ponytail: self-healing additive migration. create_all() creates missing
# TABLES but never adds missing COLUMNS to an existing table, so a DB written by
# an older version lacks any column added since (e.g. notify_line/line_channel_token).
# Reflect each model's columns and ALTER in whatever the live table is missing —
# so a version bump that adds a column just works on restart, no manual migration
# and no config loss. Additive only: never drops/renames, never touches data.
def _ensure_columns():
    from sqlalchemy import inspect as _sa_inspect
    insp = _sa_inspect(engine)
    tables = set(insp.get_table_names())
    for table in models.Base.metadata.sorted_tables:
        if table.name not in tables:
            continue  # create_all() already made brand-new tables in full
        existing = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing:
                continue
            coltype = col.type.compile(engine.dialect)
            try:
                with engine.begin() as conn:
                    conn.exec_driver_sql(
                        f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {coltype}'
                    )
                logger.warning(f"migration: added column {table.name}.{col.name} ({coltype})")
            except Exception as e:
                logger.warning(f"migration: could not add {table.name}.{col.name}: {e}")

_ensure_columns()

# One-time copy of details extracted before the cve_insights table existed
# (they lived in extra columns on cves). INSERT OR IGNORE: never overwrites.
if engine.dialect.name == "sqlite":
    with engine.begin() as _c:
        _c.exec_driver_sql("""
            INSERT OR IGNORE INTO cve_insights (cve_id, affected_versions, affected_conditions, mitigation,
                remediation, fixed_versions, iocs, extracted_at, ai_verification, ai_checked_at)
            SELECT cve_id, affected_versions, affected_conditions, mitigation, remediation, fixed_versions,
                iocs, details_fetched_at, details_verification,
                CASE WHEN details_verification IS NOT NULL THEN details_fetched_at END
            FROM cves WHERE details_fetched_at IS NOT NULL GROUP BY cve_id""")

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
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    _enforce_rate_limit(request, "token", max_attempts=5, window_seconds=60)
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
def create_user(request: Request, user: schemas.UserCreate, db: Session = Depends(get_db)):
    _enforce_rate_limit(request, "register", max_attempts=5, window_seconds=60)
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
    request: Request,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=20000),  # ponytail: cap raised so the client can pull the whole table; global date-sorted window was starving low-volume vendor feeds (Palo/Splunk/Check Point/Ubuntu)
    severity: Optional[List[str]] = Query(None),
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    search: Optional[str] = None,
    days: Optional[int] = Query(None, ge=1),  # ponytail: only CVEs published within the last N days; lighter default payload. omit = all
    db: Session = Depends(get_db)
):
    # ponytail: serve a recent identical query straight from cache (see _CVES_CACHE).
    cache_key = str(request.url.query)
    wants_gzip = "gzip" in request.headers.get("accept-encoding", "")

    def _serve(hit):
        # The ~9MB list gzips ~5x; it's compressed once at build time and reused,
        # so 100 users cost ~2MB each over the network instead of ~9MB, with no
        # per-request compression CPU.
        if wants_gzip:
            return Response(content=hit[2], media_type="application/json",
                            headers={"Content-Encoding": "gzip", "Vary": "Accept-Encoding"})
        return Response(content=hit[1], media_type="application/json", headers={"Vary": "Accept-Encoding"})

    _hit = _CVES_CACHE.get(cache_key)
    if _hit and _time.time() - _hit[0] < _CVES_TTL:
        return _serve(_hit)
    if len(_CVES_LOCKS) > 256:
        _CVES_LOCKS.clear()              # bound memory; worst case two builds race once
    with _CVES_LOCKS.setdefault(cache_key, threading.Lock()):
        _hit = _CVES_CACHE.get(cache_key)   # someone may have built it while we waited
        if _hit and _time.time() - _hit[0] < _CVES_TTL:
            return _serve(_hit)
        return _build_cves_response(cache_key, db, skip, limit, severity, vendor, product, search, days, _serve)


def _build_cves_response(cache_key, db, skip, limit, severity, vendor, product, search, days, _serve):
    _now = _time.time()
    try:
        query = db.query(models.CVE)

        if days:
            cutoff = datetime.utcnow() - timedelta(days=days)
            query = query.filter(models.CVE.published_date >= cutoff)
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

        rows = query.order_by(models.CVE.published_date.desc()).offset(skip).limit(limit).all()
        body = _CVE_LIST_ADAPTER.dump_json([schemas.CVEResponse.model_validate(r) for r in rows])
        if len(_CVES_CACHE) > 64:        # bound memory from varied filter combos
            _CVES_CACHE.clear()
        hit = (_now, body, gzip.compress(body, 6))
        _CVES_CACHE[cache_key] = hit
        return _serve(hit)
    except Exception as exc:
        # Fail-safe: DB unavailable — serve from per-source files (degraded filtering).
        logger.error(f"/cves/ DB query failed, serving from source files: {exc}")
        return source_store.query_fallback(
            severity=severity, vendor=vendor, product=product,
            search=search, skip=skip, limit=limit,
        )


@app.get("/cves/products")
def get_cve_products(db: Session = Depends(get_db)):
    """Distinct (source, product) combinations across the WHOLE table, not
    just whatever falls inside the display window. Powers the Filter by
    Source & Product panel's list of options -- a product doesn't disappear
    from the picker just because every CVE that has it happens to be older
    than the default 30-day view. Cheap: a GROUP BY, not full CVE rows.
    Must be registered before /cves/{cve_id} or FastAPI would treat
    "products" as a cve_id.
    """
    from sqlalchemy import func
    rows = (
        db.query(models.CVE.rss_source, models.CVE.product, func.count().label("count"))
        .filter(models.CVE.product.isnot(None))
        .group_by(models.CVE.rss_source, models.CVE.product)
        .all()
    )
    return [{"source": r[0], "product": r[1], "count": r[2]} for r in rows]


@app.get("/cves/{cve_id}", response_model=schemas.CVEResponse)
def get_cve(cve_id: str, db: Session = Depends(get_db)):
    cve = db.query(models.CVE).filter(models.CVE.cve_id == cve_id).first()
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve


@app.get("/cves/{cve_id}/details")
def get_cve_details(cve_id: str, db: Session = Depends(get_db)):
    """Affected versions / conditions / mitigation / remediation / fixed versions /
    IOCs for one CVE number, plus its AI summary + verification, from the
    cve_insights table. Extracted from CVE.org on first open if the background
    Threat Summary job hasn't reached it (or it's over 7 days old)."""
    if not db.query(models.CVE.cve_id).filter(models.CVE.cve_id == cve_id).first():
        raise HTTPException(status_code=404, detail="CVE not found")
    ins = threat_summary.extract(db, cve_id)
    return threat_summary.public(ins, cve_id)


@app.post("/cves/{cve_id}/verify")
def verify_cve_details(cve_id: str, db: Session = Depends(get_db)):
    """AI summary + per-field check of the extracted details against the raw
    CVE.org record (threat_summary.ai_check). Suggestions are shown alongside the
    extraction, never written over it -- a human decides."""
    if not db.query(models.CVE.cve_id).filter(models.CVE.cve_id == cve_id).first():
        raise HTTPException(status_code=404, detail="CVE not found")
    try:
        ins = threat_summary.ai_check(db, cve_id)
    except threat_summary.CheckError as e:
        msg = str(e)
        raise HTTPException(status_code=502 if msg.startswith("AI check failed") else 409, detail=msg)
    return threat_summary.public(ins, cve_id)


# ─── Threat Summary Management (threat_summary.py, vnotice-threat-summary.timer) ───

@app.get("/settings/threat-summary")
def get_threat_summary_settings(db: Session = Depends(get_db)):
    return {**threat_summary.get_scope(db), "stats": threat_summary.stats(db)}


@app.put("/settings/threat-summary")
async def put_threat_summary_settings(request: Request, db: Session = Depends(get_db)):
    body = await request.json()
    scope = threat_summary.save_scope(db, body.get("enabled", True), body.get("sources") or {})
    logger.warning(f"threat summary scope saved ({len(scope['sources'])} source(s), enabled={scope['enabled']})")
    return {**scope, "stats": threat_summary.stats(db)}


_TS_RUNNING = threading.Lock()


@app.post("/settings/threat-summary/run")
def run_threat_summary_now(retry_failed: bool = False, db: Session = Depends(get_db)):
    """Start one batch now in the background (the timer runs one every 10 min)."""
    cleared = threat_summary.clear_errors(db) if retry_failed else 0
    if not _TS_RUNNING.acquire(blocking=False):
        return {"result": "a batch is already running"}

    def _job():
        try:
            logger.warning(f"threat summary (manual): {threat_summary.run()}")
        finally:
            _TS_RUNNING.release()
    threading.Thread(target=_job, daemon=True).start()
    return {"result": f"batch started (up to {threat_summary.BATCH} CVEs)"
                      + (f"; cleared {cleared} failed AI check(s) for retry" if cleared else "")}


# ─── AI provider settings (same contract as Sabler's /api/settings/llm) ───

@app.get("/settings/llm")
def get_llm_settings():
    """Everything the Settings page may show. The API key is never included."""
    return llm.public_settings()


@app.put("/settings/llm")
async def put_llm_settings(request: Request):
    body = await request.json()
    try:
        llm.save(body.get("provider", ""), body.get("model", ""), body.get("api_key", ""), body.get("verify_model", ""))
    except llm.LLMError as e:
        raise HTTPException(status_code=400, detail=str(e))
    logger.warning(f"AI provider settings saved (provider={body.get('provider')})")
    return llm.public_settings()


@app.delete("/settings/llm")
def delete_llm_key():
    llm.remove_key()
    logger.warning("AI provider key removed")
    return llm.public_settings()


@app.post("/settings/llm/test")
def test_llm_key():
    try:
        return {"reply": llm.test()}
    except llm.LLMError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ─── Admin 10-minute summary (admin_digest.py, vnotice-admin-digest.timer) ───

@app.get("/settings/admin-digest")
def get_admin_digest_settings():
    """Webhook URLs are secrets: only their last 6 characters are ever returned."""
    return admin_digest.public_settings()


@app.put("/settings/admin-digest")
async def put_admin_digest_settings(request: Request):
    body = await request.json()
    webhooks = [u.strip() for u in body.get("webhooks", []) if isinstance(u, str) and u.strip()]
    for u in webhooks:
        _validate_teams_webhook(u)   # same allowlist as user Teams alerts: no arbitrary hosts
    if body.get("keep_existing") and not webhooks:
        webhooks = admin_digest._webhooks()
    admin_digest.save(webhooks, body.get("enabled", True))
    logger.warning(f"admin digest settings saved ({len(webhooks)} webhook(s), enabled={body.get('enabled', True)})")
    return admin_digest.public_settings()


@app.post("/settings/admin-digest/test")
def test_admin_digest():
    try:
        return {"result": admin_digest.run(test=True)}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not post to the webhook: {e}")


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


def _trigger_matches(trigger, cve) -> bool:
    if trigger.keyword and trigger.keyword.lower() not in (
        (cve.title or "") + " " + (cve.description or "")
    ).lower():
        return False
    if trigger.vendor and trigger.vendor.lower() not in (cve.vendor or "").lower():
        return False
    if trigger.product and trigger.product.lower() not in (cve.product or "").lower():
        return False
    if trigger.feed_source and trigger.feed_source.strip().lower() != (cve.rss_source or "").strip().lower():
        return False
    if trigger.min_severity and _SEVERITY_ORDER.get((cve.severity or "").lower(), 0) < \
            _SEVERITY_ORDER.get(trigger.min_severity.lower(), 0):
        return False
    if trigger.min_cvss_score is not None and (cve.cvss_score or 0) < float(trigger.min_cvss_score):
        return False
    return True


def _alert_email(cve):
    sev = (cve.severity or "Medium").upper()
    ref = cve.reference_url or ""
    desc = (cve.description or "")[:300]
    epss_str = f"{cve.epss * 100:.2f}%" if cve.epss is not None else "N/A"
    cvss_str = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "N/A"
    published_str = cve.published_date.strftime("%Y-%m-%d") if cve.published_date else "N/A"
    subject = f"[Vnotice Alert] {cve.cve_id} — {sev}"
    body = (
        '<html><body style="font-family:sans-serif">'
        f'<h2 style="color:#c0392b">🚨 CVE Alert: {cve.cve_id}</h2><table>'
        f'<tr><td><b>Title</b></td><td>{cve.title or cve.cve_id}</td></tr>'
        f'<tr><td><b>Severity</b></td><td>{sev}</td></tr>'
        f'<tr><td><b>CVSS</b></td><td>{cvss_str}</td></tr>'
        f'<tr><td><b>EPSS</b></td><td>{epss_str}</td></tr>'
        f'<tr><td><b>Published</b></td><td>{published_str}</td></tr>'
        + (f'<tr><td><b>Description</b></td><td>{desc}</td></tr>' if desc else '')
        + (f'<tr><td><b>Reference</b></td><td><a href="{ref}">{ref}</a></td></tr>' if ref else '')
        + '</table></body></html>'
    )
    return subject, body


def _dest_hash(dest: str) -> str:
    import hashlib
    return hashlib.sha256(dest.encode("utf-8")).hexdigest()


async def _evaluate_triggers(user_id: str = "", db_url: str = ""):
    """After a sync, alert every user whose triggers match a newly added CVE.
    Runs as a background task.

    Matching happens across ALL users first, then delivery is per destination:
      * each user gets a CVE at most once, however many of their triggers match
        it and however many feeds it arrived from;
      * everyone subscribed to the same CVE via the same mail account gets ONE
        email with all of them as (Bcc) recipients, not one email each;
      * a webhook shared by several users is posted to once;
      * every delivery is recorded in sent_alerts and checked first, so an
        overlapping sync never re-sends it.

    An empty user_id means "every user that has triggers" -- the hourly auto-sync
    runs as a service account that owns no triggers itself.
    """
    import logging as _log
    _logger = _log.getLogger(__name__)
    db = SessionLocal()
    try:
        uids = [user_id] if user_id else [
            str(r[0]) for r in db.query(models.NotificationTrigger.user_id).distinct().all()
        ]
        recent_cutoff = datetime.utcnow() - timedelta(minutes=10)
        recent_cves = db.query(models.CVE).filter(models.CVE.created_at >= recent_cutoff).all()
        if not uids or not recent_cves:
            return

        users = []
        for uid in uids:
            cfg = db.query(models.UserConfig).filter(models.UserConfig.user_id == uid).first()
            trigs = db.query(models.NotificationTrigger).filter(models.NotificationTrigger.user_id == uid).all()
            if cfg and trigs:
                users.append((cfg, trigs))

        # cve_id -> (a representative CVE row, [config of each matched user]); one entry per CVE ID
        matched = {}
        for cve in recent_cves:
            for cfg, trigs in users:
                if any(_trigger_matches(t, cve) for t in trigs):
                    _, cfgs = matched.setdefault(cve.cve_id, (cve, []))
                    if cfg not in cfgs:
                        cfgs.append(cfg)
        if not matched:
            return

        already = {(r.cve_id, r.channel, r.dest_hash) for r in db.query(models.SentAlert).filter(
            models.SentAlert.cve_id.in_(list(matched))).all()}

        def _is_new(cve_id, channel, dest):
            return (cve_id, channel, _dest_hash(dest)) not in already

        def _record(cve_id, channel, dest):
            db.add(models.SentAlert(cve_id=cve_id, channel=channel, dest_hash=_dest_hash(dest)))
            already.add((cve_id, channel, _dest_hash(dest)))

        async with httpx.AsyncClient(timeout=10.0) as client:
            async def _post_ok(url, **kw):
                resp = await client.post(url, **kw)
                resp.raise_for_status()   # a 4xx/5xx is a failed delivery, not a success

            for cve_id, (cve, cfgs) in matched.items():
                kw = dict(
                    title=cve.title or cve.cve_id, severity=cve.severity or "Medium", cve_id=cve.cve_id,
                    description=(cve.description or "")[:300], reference_url=cve.reference_url,
                    epss=cve.epss, cvss_score=cve.cvss_score, published_date=cve.published_date,
                )

                # Distinct webhook-style destinations across every matched user.
                hooks = {}   # (channel, destination) -> (url, request kwargs)
                for cfg in cfgs:
                    if cfg.notify_teams and cfg.teams_webhook:
                        hooks[("teams", cfg.teams_webhook)] = (cfg.teams_webhook, {"json": _build_teams_card(**kw)})
                    if cfg.notify_discord and cfg.discord_webhook:
                        hooks[("discord", cfg.discord_webhook)] = (cfg.discord_webhook, {"json": _build_discord_payload(**kw)})
                    if cfg.notify_telegram and cfg.telegram_bot_token and cfg.telegram_chat_id:
                        hooks[("telegram", f"{cfg.telegram_bot_token}|{cfg.telegram_chat_id}")] = (
                            f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendMessage",
                            {"json": {"chat_id": cfg.telegram_chat_id, "text": _build_telegram_text(**kw), "parse_mode": "HTML"}})
                    if cfg.notify_line and cfg.line_channel_token:
                        hooks[("line", cfg.line_channel_token)] = (
                            "https://api.line.me/v2/bot/message/broadcast",
                            {"headers": {"Authorization": f"Bearer {cfg.line_channel_token}"},
                             "json": {"messages": [{"type": "text", "text": _build_line_text(**kw)}]}})

                for (channel, dest), (url, req) in hooks.items():
                    if not _is_new(cve_id, channel, dest):
                        continue
                    try:
                        await _post_ok(url, **req)
                        _record(cve_id, channel, dest)
                        _logger.warning(f"alert sent: {cve_id} via {channel}")
                    except Exception as exc:
                        _logger.error(f"Trigger alert failed for {cve_id} via {channel}: {exc!r}")

                # Email: ONE message per sending mail account, with all its recipients together.
                mail_groups = {}   # (host, port, user) -> [password, [recipients]]
                for cfg in cfgs:
                    if cfg.notify_email and cfg.smtp_host and cfg.smtp_username and cfg.smtp_password and cfg.smtp_to_address:
                        group = mail_groups.setdefault((cfg.smtp_host, cfg.smtp_port or 587, cfg.smtp_username),
                                                       [cfg.smtp_password, []])
                        to = cfg.smtp_to_address.strip()
                        if to not in group[1] and _is_new(cve_id, "email", to.lower()):
                            group[1].append(to)
                subject, body = _alert_email(cve)
                for (host, port, user), (pw, recipients) in mail_groups.items():
                    if not recipients:
                        continue
                    try:
                        await asyncio.get_event_loop().run_in_executor(
                            None, _send_smtp, host, port, user, pw, recipients, subject, body)
                        for to in recipients:
                            _record(cve_id, "email", to.lower())
                        _logger.warning(f"alert sent: {cve_id} via email, one message to {len(recipients)} recipient(s)")
                    except Exception as exc:
                        _logger.error(f"Trigger alert failed for {cve_id} via email: {exc!r}")
                db.commit()
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
    # Retention window: only ever store CVEs published in the last 30 days.
    # Enforced twice -- skipped on ingest below, and swept from the table
    # near the end of this function so it also catches rows that have aged
    # out since they were inserted (every sync run re-checks published_date).
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

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
            pub = item.get("published_date")
            if pub:
                pub_naive = pub.replace(tzinfo=None) if getattr(pub, "tzinfo", None) else pub
                if pub_naive < thirty_days_ago:
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
        # NVD vendor-scoped feeds (e.g. Ivanti by keyword; F5 / MobileIron by CPE
        # vendor — their own sites are unscrapeable). Must precede the generic NVD
        # branch below. Routed by which filter param the feed URL carries.
        if "services.nvd.nist.gov" in feed.url and "keywordSearch=" in feed.url:
            from urllib.parse import urlparse, parse_qs
            kw = (parse_qs(urlparse(feed.url).query).get("keywordSearch") or [""])[0]
            if kw:
                _insert_items(RSSIngestionService.fetch_nvd_by_keyword(kw), feed.name)
            continue
        if "services.nvd.nist.gov" in feed.url and "virtualMatchString=" in feed.url:
            from urllib.parse import urlparse, parse_qs
            cpe = (parse_qs(urlparse(feed.url).query).get("virtualMatchString") or [""])[0]
            if cpe:
                _insert_items(RSSIngestionService.fetch_nvd_by_cpe(cpe), feed.name)
            continue
        if "services.nvd.nist.gov" in feed.url:
            # fetch_nvd_api's own CPE-based lookup only succeeds once NVD has
            # analysed a CVE (added Known Affected Software Configurations),
            # which lags initial publication -- so brand-new CVEs come back
            # "Various"/"Various" by construction, not by bug. Fall back to
            # the same title-keyword heuristic the generic RSS path already
            # uses, so a recognisable product (WordPress, Apache, GitLab, ...)
            # isn't left generic just because NVD hasn't gotten to it yet.
            nvd_items = RSSIngestionService.fetch_nvd_api()
            for it in nvd_items:
                if it["vendor"] == "Various" and it["product"] == "Various":
                    v, p = _infer_vendor_product(feed.name, it["title"])
                    if v != "Various":
                        it["vendor"], it["product"] = v, p
            _insert_items(nvd_items, feed.name)
            continue
        if "advisory.splunk.com" in feed.url:
            _insert_items(RSSIngestionService.fetch_splunk_advisories(), feed.name)
            continue
        if "fortiguard" in feed.url or "fortinet.com" in feed.url:
            # Fortinet's own PSIRT RSS, but parsed by a dedicated fetcher: the
            # generic RSS path minted unstable CVE-FEED-<hash> ids and randomised
            # CVSS/severity. This keeps the real CVSS + stable FG-IR/CVE id.
            _insert_items(RSSIngestionService.fetch_fortinet_advisories(), feed.name)
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
            # Skip items older than the retention window
            pub = item.get("published_date")
            if pub:
                pub_naive = pub.replace(tzinfo=None) if getattr(pub, "tzinfo", None) else pub
                if pub_naive < thirty_days_ago:
                    continue
            key = (item["cve_id"], feed.name)
            if key not in existing_pairs:
                vendor, product = _infer_vendor_product(feed.name, item["title"])
                # This feed carries no CVSS data of its own — look the CVE up
                # in the NVD (the authoritative source) instead of guessing.
                nvd = RSSIngestionService.fetch_nvd_details(item["cve_id"])
                real_epss = RSSIngestionService.fetch_real_epss_score(item["cve_id"])
                record = {
                    "cve_id": item["cve_id"],
                    "title": item["title"],
                    "description": item["description"],
                    "severity": nvd["severity"] if nvd else None,
                    "cvss_score": nvd["cvss_score"] if nvd else None,
                    "epss": real_epss if real_epss > 0 else None,
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

    # Retry EPSS for previously-null CVEs too -- the block above only covers
    # rows inserted THIS sync. A CVE too new for EPSS at insert time would
    # otherwise stay "N/A" forever, since nothing else ever re-checks it,
    # short of someone manually clicking "Refresh Missing EPSS" in Settings.
    # Re-querying here every hour means it self-heals once FIRST.org actually
    # scores it (most stay null because NVD rejected the CVE, which is a
    # real, permanent N/A -- this just stops silently missing the ones that
    # do get scored later).
    stale_null = db.query(models.CVE).filter(
        models.CVE.epss.is_(None), models.CVE.cve_id.like("CVE-%")
    ).all()
    if stale_null:
        retry_scores = RSSIngestionService.fetch_epss_batch([r.cve_id for r in stale_null])
        for r in stale_null:
            val = retry_scores.get((r.cve_id or "").upper())
            if val is not None:
                r.epss = val

    # Same idea for "Various"/"Various" NVD CVEs, but via the single-CVE NVD
    # lookup (fetch_nvd_details), not the batched EPSS one -- NVD only knows a
    # CVE's real vendor/product once its own analysts add CPE ("Known
    # Affected Software Configurations") data, which lags publication. A CVE
    # too new for that at insert time gets a real product name automatically
    # the moment NVD adds it, no keyword list to maintain and no manual
    # re-sync needed. Capped per run (one HTTP call each, unlike the batched
    # EPSS retry) so a large backlog can't turn every hourly sync into a
    # multi-minute run or trip NVD's rate limit -- it works through the
    # backlog gradually, oldest-discovered first.
    stale_various = db.query(models.CVE).filter(
        models.CVE.vendor == "Various", models.CVE.rss_source == "NVD / NIST CVE"
    ).order_by(models.CVE.created_at.asc()).limit(30).all()
    for r in stale_various:
        nvd = RSSIngestionService.fetch_nvd_details(r.cve_id)
        if nvd and nvd.get("vendor") and nvd["vendor"] != "Various":
            r.vendor, r.product = nvd["vendor"], nvd["product"]

    # Fail-safe: write each source's CVEs to its per-source file BEFORE the DB
    # commit, so the durable copy survives even if the commit fails.
    for src, recs in synced_by_source.items():
        source_store.write_source(src, recs)

    # No hard-delete retention sweep -- the database keeps every CVE it has
    # ever ingested (needed so the Centralize integration sync can pull older
    # findings without a race against a purge). "30 days" is a DISPLAY
    # default only, enforced by the `days` query param on GET /cves/, not by
    # deleting rows -- older data is still there for anyone who asks for it.

    # Persist feed/scraper config to UserConfig so other clients can load it
    cfg = _get_or_create_config(current_user, db)
    cfg.feeds_config = [f.model_dump() for f in sync_req.feeds]
    cfg.scrapers_config = [s.model_dump() for s in sync_req.scrapers]

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database transaction error: {e}")
    _CVES_CACHE.clear()   # ponytail: new CVEs written ⇒ drop the /cves/ response cache

    # Evaluate notification triggers against newly added CVEs (background, non-blocking).
    # Empty user_id => every user with triggers; the caller is normally the auto-sync
    # service account, which owns none of them.
    if new_cves_added > 0:
        background_tasks.add_task(_evaluate_triggers, "", str(engine.url))

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
    _CVES_CACHE.clear()   # ponytail: rows deleted ⇒ drop the /cves/ response cache
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

# ponytail: cache the process scan — process_iter() over every PID on the box is
# the dominant /health/ cost, and the backend/frontend PIDs rarely change.
_SUBPROC_CACHE: dict = {"ts": 0.0, "data": []}
_SUBPROC_TTL = 15.0

def _vnotice_subprocesses() -> list:
    """Best-effort list of the OS processes that make up this deployment —
    backend (uvicorn) + frontend (Next.js) — so Engine Status shows every
    subprocess, not just the API process. ponytail: psutil cmdline match,
    scoped to the current user's own processes."""
    now = _time.time()
    if _SUBPROC_CACHE["data"] and now - _SUBPROC_CACHE["ts"] < _SUBPROC_TTL:
        return _SUBPROC_CACHE["data"]
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
    _SUBPROC_CACHE["ts"] = now
    _SUBPROC_CACHE["data"] = procs
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
        result["cpu_percent"] = psutil.cpu_percent(interval=None)  # ponytail: non-blocking (was interval=0.2)
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
            "cpu_percent": proc.cpu_percent(interval=None),  # ponytail: non-blocking (was interval=0.1)
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
    """Backfill REAL EPSS scores from FIRST.org (batched) for CVEs still N/A
    -- the dashboard's "Refresh N/A EPSS" button. Already-scored CVEs are never
    re-queried; a CVE FIRST.org still has no score for stays None."""
    rows = db.query(models.CVE).filter(models.CVE.epss.is_(None)).all()
    if not rows:
        return {"total": 0, "with_epss": 0, "na": 0}
    scores = RSSIngestionService.fetch_epss_batch([r.cve_id for r in rows])
    found = 0
    for r in rows:
        val = scores.get((r.cve_id or "").upper())
        if val is not None:
            r.epss = val
            found += 1
    db.commit()
    _CVES_CACHE.clear()   # ponytail: epss updated ⇒ drop the /cves/ response cache
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
                      description: Optional[str], reference_url: Optional[str],
                      epss: Optional[float] = None, cvss_score: Optional[float] = None,
                      published_date: Optional[datetime] = None) -> dict:
    # The Teams Workflow ("Post card when a webhook request is received") requires
    # an Adaptive Card wrapped in the attachments envelope below — a plain
    # {"text": ...} body is accepted at HTTP level (202) but the flow then fails
    # to post it. So we always send a proper Adaptive Card.
    color_map = {"critical": "attention", "high": "warning", "medium": "accent", "low": "good"}
    color = color_map.get((severity or "").lower(), "default")
    facts = [{"title": "CVE ID", "value": cve_id}, {"title": "Severity", "value": severity}]
    if cvss_score is not None:
        facts.append({"title": "CVSS", "value": f"{cvss_score:.1f}"})
    if epss is not None:
        facts.append({"title": "EPSS", "value": f"{epss * 100:.2f}%"})
    if published_date is not None:
        facts.append({"title": "Published", "value": published_date.strftime("%Y-%m-%d")})
    body = [{"type": "TextBlock", "text": f"🚨 {title}", "weight": "bolder",
             "size": "medium", "color": color, "wrap": True}]
    if description:
        body.append({"type": "TextBlock", "text": description, "wrap": True, "isSubtle": True})
    body.append({"type": "FactSet", "facts": facts})
    card: dict = {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.4",
        "body": body,
    }
    if reference_url:
        # FactSet values render as plain text in Teams (not clickable) — an
        # Action.OpenUrl button is the Adaptive Card way to get a real link.
        card["actions"] = [{"type": "Action.OpenUrl", "title": "View Advisory", "url": reference_url}]
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": card,
        }],
    }


@app.post("/notifications/teams", status_code=200)
async def send_teams_alert(req: schemas.TeamsAlertRequest):
    """Send a CVE alert to a Microsoft Teams channel via Incoming Webhook."""
    _validate_teams_webhook(req.webhook_url)
    payload = _build_teams_card(req.title, req.severity, req.cve_id,
                                req.description, req.reference_url, req.epss, req.cvss_score,
                                req.published_date)
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
                           description: Optional[str], reference_url: Optional[str],
                           epss: Optional[float] = None, cvss_score: Optional[float] = None,
                           published_date: Optional[datetime] = None) -> dict:
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
                          description: Optional[str], reference_url: Optional[str],
                          epss: Optional[float] = None, cvss_score: Optional[float] = None,
                          published_date: Optional[datetime] = None) -> str:
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


def _build_line_text(title: str, severity: str, cve_id: str,
                     description: Optional[str], reference_url: Optional[str],
                     epss: Optional[float] = None, cvss_score: Optional[float] = None,
                     published_date: Optional[datetime] = None) -> str:
    # LINE text messages are plain text (no HTML), 5000-char limit.
    lines = [f"🚨 [{cve_id}] {title}", f"Severity: {severity.upper()}"]
    if description:
        lines.append(f"\n{description[:300]}{'…' if len(description or '') > 300 else ''}")
    if reference_url:
        lines.append(f"\n{reference_url}")
    return "\n".join(lines)


@app.post("/notifications/test-line", status_code=200)
async def test_line_broadcast(
    req: schemas.LineTestRequest,
):
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                "https://api.line.me/v2/bot/message/broadcast",
                headers={"Authorization": f"Bearer {req.channel_token}"},
                json={"messages": [{"type": "text",
                    "text": "✅ CVE Monitor — Test Alert\nLINE notifications are configured correctly."}]},
            )
        if resp.status_code == 200:
            return {"status": "ok", "message": "Test message broadcast to LINE."}
        try:
            detail = resp.json().get("message", resp.text[:200])
        except Exception:
            detail = resp.text[:200]
        raise HTTPException(status_code=502, detail=f"LINE error ({resp.status_code}): {detail}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="LINE request timed out.")
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
               to_address, subject: str, body_html: str) -> None:
    """to_address: one address, or a list -- several people subscribed to the same
    product get ONE email, with each other's addresses hidden (Bcc)."""
    recipients = [a for a in ([to_address] if isinstance(to_address, str) else list(to_address)) if (a or "").strip()]
    if len(recipients) > 1:
        return _send_smtp_bcc(host, port, username, password, recipients, subject, body_html)
    to_address = recipients[0] if recipients else ""
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


def _send_smtp_bcc(host, port, username, password, recipients, subject, body_html):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = username
    msg["To"] = "Vnotice subscribers <%s>" % username   # recipients go in the envelope only (Bcc)
    msg.attach(MIMEText(body_html, "html"))
    ctx = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=30) as server:
            server.login(username, password)
            server.sendmail(username, recipients, msg.as_string())
    else:
        with smtplib.SMTP(host, port, timeout=30) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.login(username, password)
            server.sendmail(username, recipients, msg.as_string())


@app.post("/notifications/email", status_code=200)
async def send_email_alert(
    req: schemas.EmailAlertRequest,
    current_user: models.User = Depends(auth.get_current_user),
):
    subject = f"[Vnotice Alert] {req.cve_id} — {req.severity.upper()}"
    epss_str = f"{req.epss * 100:.2f}%" if req.epss is not None else "N/A"
    cvss_str = f"{req.cvss_score:.1f}" if req.cvss_score is not None else "N/A"
    published_str = req.published_date.strftime("%Y-%m-%d") if req.published_date else None
    body = f"""
<html><body style="font-family:sans-serif">
<h2 style="color:#c0392b">🚨 CVE Alert: {req.cve_id}</h2>
<table><tr><td><b>Title</b></td><td>{req.title}</td></tr>
<tr><td><b>Severity</b></td><td>{req.severity.upper()}</td></tr>
<tr><td><b>CVSS</b></td><td>{cvss_str}</td></tr>
<tr><td><b>EPSS</b></td><td>{epss_str}</td></tr>
{'<tr><td><b>Published</b></td><td>' + published_str + '</td></tr>' if published_str else ''}
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
        epss_str = f"{req.epss * 100:.2f}%" if req.epss is not None else "N/A"
        cvss_str = f"{req.cvss_score:.1f}" if req.cvss_score is not None else "N/A"
        subject = f"[Vnotice Alert] {req.cve_id} — {sev}"
        body = (
            '<html><body style="font-family:sans-serif">'
            f'<h2 style="color:#c0392b">🚨 CVE Alert: {req.cve_id}</h2><table>'
            f'<tr><td><b>Title</b></td><td>{req.title or req.cve_id}</td></tr>'
            f'<tr><td><b>Severity</b></td><td>{sev}</td></tr>'
            f'<tr><td><b>CVSS</b></td><td>{cvss_str}</td></tr>'
            f'<tr><td><b>EPSS</b></td><td>{epss_str}</td></tr>'
            + (f'<tr><td><b>Published</b></td><td>{req.published_date}</td></tr>' if req.published_date else '')
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
    if not any([trigger.keyword, trigger.vendor, trigger.product, trigger.feed_source,
                trigger.min_severity, trigger.min_cvss_score is not None]):
        raise HTTPException(status_code=422, detail="At least one trigger condition is required.")
    row = models.NotificationTrigger(
        user_id=current_user.id,
        keyword=trigger.keyword,
        vendor=trigger.vendor,
        product=trigger.product,
        min_severity=trigger.min_severity,
        min_cvss_score=trigger.min_cvss_score,
        feed_source=trigger.feed_source,
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
