"""Hourly resource sampler for the Vnotice processes (backend + frontend).

Tracks what *our* app consumes — summed CPU% and memory (RSS) of the uvicorn
and Next.js processes, plus the app's on-disk data footprint — so long-run
growth / leaks are visible. ponytail: a tiny JSON ring buffer on disk.
One sample per hour bucket; at most 365*24 rows are kept.
"""
import os
import json
import time
import asyncio
import tempfile
from datetime import datetime, timezone

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_FILE = os.path.join(_DIR, "resource_usage.json")
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
_MAX = 365 * 24          # one sample/hour for a year
_INTERVAL = 3600         # seconds between samples


def _now_hour_iso():
    return datetime.now(timezone.utc).replace(
        minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00:00Z")


def load_history():
    try:
        with open(_FILE, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []


def _save(rows):
    os.makedirs(_DIR, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=_DIR, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(rows, f)
        os.replace(tmp, _FILE)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def _app_processes(psutil):
    """Our deployment's processes (uvicorn backend + Next.js frontend),
    scoped to the current user."""
    try:
        me = psutil.Process().username()
    except Exception:
        me = None
    procs = []
    for p in psutil.process_iter(["cmdline", "name", "username"]):
        try:
            if me is not None and p.info.get("username") != me:
                continue
            cmd = " ".join(p.info.get("cmdline") or []).lower()
            name = (p.info.get("name") or "").lower()
            if ("uvicorn" in cmd and "main:app" in cmd) or \
               ("next-server" in name or "next-server" in cmd):
                procs.append(p)
        except Exception:
            continue
    return procs


def _app_disk_mb():
    """On-disk footprint that grows with use: the SQLite DB + the data dir."""
    total = 0
    for path in (os.path.join(_BACKEND_DIR, "cvedb.sqlite"),
                 os.path.join(_BACKEND_DIR, "data")):
        try:
            if os.path.isfile(path):
                total += os.path.getsize(path)
            elif os.path.isdir(path):
                for root, _dirs, files in os.walk(path):
                    for fn in files:
                        try:
                            total += os.path.getsize(os.path.join(root, fn))
                        except OSError:
                            pass
        except OSError:
            pass
    return round(total / 1e6, 2)


def record_sample():
    """Sample our processes' summed CPU% + RSS and the app data footprint."""
    try:
        import psutil
    except ImportError:
        return None
    procs = _app_processes(psutil)
    # Prime per-process CPU counters, wait, then read => CPU% over the interval.
    for p in procs:
        try:
            p.cpu_percent(None)
        except Exception:
            pass
    time.sleep(1)
    cpu = 0.0
    rss = 0
    for p in procs:
        try:
            cpu += p.cpu_percent(None)
            rss += p.memory_info().rss
        except Exception:
            continue
    sample = {
        "t": _now_hour_iso(),
        "cpu_pct": round(cpu, 1),
        "mem_mb": round(rss / 1e6, 1),
        "disk_mb": _app_disk_mb(),
        "procs": len(procs),
    }
    rows = load_history()
    if rows and rows[-1].get("t") == sample["t"]:
        rows[-1] = sample           # already sampled this hour → overwrite
    else:
        rows.append(sample)
    if len(rows) > _MAX:
        rows = rows[-_MAX:]
    _save(rows)
    return sample


async def sampler_loop():
    """Record immediately on startup, then once per hour, forever."""
    while True:
        try:
            await asyncio.get_event_loop().run_in_executor(None, record_sample)
        except Exception:
            pass
        await asyncio.sleep(_INTERVAL)
