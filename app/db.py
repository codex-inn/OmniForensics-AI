import sqlite3
from .config import DB_PATH, ensure_dirs

def connect():
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def init_db():
    with connect() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS cases(
          id TEXT PRIMARY KEY, title TEXT NOT NULL,
          description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence(
          id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
          original_name TEXT NOT NULL, stored_name TEXT NOT NULL,
          sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL,
          detected_mime TEXT NOT NULL, uploaded_at TEXT NOT NULL,
          analysis_json TEXT NOT NULL,
          tags TEXT NOT NULL DEFAULT '',
          source_description TEXT NOT NULL DEFAULT '',
          collected_by TEXT NOT NULL DEFAULT '',
          acquired_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS notes(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id TEXT NOT NULL REFERENCES cases(id),
          body TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT,
          event TEXT, details_json TEXT, created_at TEXT,
          prev_hash TEXT, event_hash TEXT
        );
        CREATE TABLE IF NOT EXISTS custody(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          evidence_id TEXT NOT NULL REFERENCES evidence(id),
          action TEXT NOT NULL,
          handler TEXT NOT NULL DEFAULT '',
          location TEXT NOT NULL DEFAULT '',
          details TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          audit_event_hash TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
        CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence(sha256);
        CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody(evidence_id, id);
        """)
        # Migrate databases created by earlier prototype versions.
        audit_columns = {row["name"] for row in conn.execute("PRAGMA table_info(audit)")}
        if "prev_hash" not in audit_columns:
            conn.execute("ALTER TABLE audit ADD COLUMN prev_hash TEXT")
        if "event_hash" not in audit_columns:
            conn.execute("ALTER TABLE audit ADD COLUMN event_hash TEXT")
        evidence_columns = {row["name"] for row in conn.execute("PRAGMA table_info(evidence)")}
        for column in ("tags", "source_description", "collected_by", "acquired_at"):
            if column not in evidence_columns:
                conn.execute(f"ALTER TABLE evidence ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
