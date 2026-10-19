import sqlite3
from .config import DB_PATH, ensure_dirs

def connect():
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
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
          analysis_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          case_id TEXT NOT NULL REFERENCES cases(id),
          body TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT,
          event TEXT, details_json TEXT, created_at TEXT
        );
        """)
