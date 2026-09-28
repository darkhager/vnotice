import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Load .env file if present (local development)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cvedb.sqlite")


engine_kwargs = {}
if DATABASE_URL.startswith("sqlite"):
    # timeout: a writer waits up to 30s for a lock instead of failing at once
    # with "database is locked" when another write (e.g. the hourly sync) is busy.
    engine_kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}

engine = create_engine(DATABASE_URL, **engine_kwargs)

if DATABASE_URL.startswith("sqlite"):
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _sqlite_wal(dbapi_conn, _):
        # WAL: readers never block the writer and the writer never blocks readers,
        # so dozens of users browsing isn't stalled while the hourly sync writes.
        # Persistent in the DB file; re-asserting it per connection is a no-op.
        # (Backups use the online backup API, which is WAL-safe.)
        dbapi_conn.execute("PRAGMA journal_mode=WAL")
        dbapi_conn.execute("PRAGMA synchronous=NORMAL")   # safe with WAL, far fewer fsyncs
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
