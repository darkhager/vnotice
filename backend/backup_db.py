"""Snapshot the live database + per-source data files into ~/backups.

Run before every deploy and daily (vnotice-backup.timer). Uses the SQLite online
backup API for a consistent copy while the app is running, tars the data/ dir,
and prunes snapshots older than the retention window.

    python backup_db.py            # default 14-day retention
    BACKUP_RETENTION_DAYS=30 python backup_db.py
"""
import os
import sys
import glob
import time
import sqlite3
import tarfile
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "cvedb.sqlite")
DATA = os.path.join(BASE, "data")
DEST = os.path.expanduser("~/backups")
RETENTION_DAYS = int(os.getenv("BACKUP_RETENTION_DAYS", "14"))


def main():
    os.makedirs(DEST, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    made = []

    if os.path.exists(DB):
        dst = os.path.join(DEST, f"cvedb-{stamp}.sqlite")
        src = sqlite3.connect(DB)
        bak = sqlite3.connect(dst)
        try:
            with bak:
                src.backup(bak)          # consistent online snapshot
        finally:
            bak.close()
            src.close()
        made.append(dst)

    if os.path.isdir(DATA):
        tarpath = os.path.join(DEST, f"data-{stamp}.tar.gz")
        with tarfile.open(tarpath, "w:gz") as t:
            t.add(DATA, arcname="data")
        made.append(tarpath)

    # prune anything older than the retention window
    cutoff = time.time() - RETENTION_DAYS * 86400
    pruned = 0
    for f in glob.glob(os.path.join(DEST, "cvedb-*.sqlite")) + glob.glob(os.path.join(DEST, "data-*.tar.gz")):
        if os.path.getmtime(f) < cutoff:
            os.remove(f)
            pruned += 1

    ts = datetime.now().isoformat()
    print(f"[{ts}] backup ok: {', '.join(os.path.basename(m) for m in made) or 'nothing'} | pruned {pruned}")


if __name__ == "__main__":
    sys.exit(main())
