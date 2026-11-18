import sqlite3
from pathlib import Path

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS source_file(id INTEGER PRIMARY KEY, name TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, raw BLOB NOT NULL DEFAULT X'');
CREATE TABLE IF NOT EXISTS batch(id TEXT PRIMARY KEY, min_temp REAL NOT NULL, max_temp REAL NOT NULL, max_excursion_min INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS box(id TEXT PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES batch(id));
CREATE TABLE IF NOT EXISTS raw_event(id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL REFERENCES source_file(id), line_no INTEGER NOT NULL, kind TEXT NOT NULL, device TEXT NOT NULL, seq INTEGER NOT NULL, box_id TEXT, event_time TEXT NOT NULL, payload TEXT NOT NULL, hash TEXT NOT NULL, UNIQUE(source_id,line_no));
CREATE TABLE IF NOT EXISTS issue(id INTEGER PRIMARY KEY, event_id INTEGER REFERENCES raw_event(id), code TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS run(id TEXT PRIMARY KEY, rules_version TEXT NOT NULL, source_digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES run(id), subject_id TEXT NOT NULL, source_id INTEGER REFERENCES source_file(id), object_kind TEXT NOT NULL, object_id INTEGER NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS decision(box_id TEXT PRIMARY KEY REFERENCES box(id), result TEXT NOT NULL, detail TEXT NOT NULL, rules_version TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES run(id));

-- Content-addressable archive: immutable per-source manifests, generations,
-- reader pins and garbage-collection ledgers. A manifest row is never mutated;
-- new publications append a new row with a new per-source generation.
CREATE TABLE IF NOT EXISTS cas_manifest(
  manifest_id TEXT PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES source_file(id),
  representation TEXT NOT NULL,
  source_gen INTEGER NOT NULL,
  source_hash TEXT NOT NULL,
  byte_length INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('staged','published','aborted')),
  manifest_json TEXT NOT NULL,
  created_at REAL NOT NULL,
  published_at REAL,
  aborted_at REAL,
  UNIQUE(source_id,representation,source_gen)
);
CREATE INDEX IF NOT EXISTS idx_cas_manifest_lookup ON cas_manifest(source_id,representation,status,source_gen);
CREATE TABLE IF NOT EXISTS cas_pointer(
  source_id INTEGER PRIMARY KEY REFERENCES source_file(id),
  representation TEXT NOT NULL,
  manifest_id TEXT NOT NULL REFERENCES cas_manifest(manifest_id),
  source_gen INTEGER NOT NULL,
  switched_at REAL NOT NULL,
  blob_reclaimed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS cas_pin(
  pin_id TEXT PRIMARY KEY,
  generation INTEGER NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cas_generation(generation INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS cas_gc_log(
  id INTEGER PRIMARY KEY,
  ran_at REAL NOT NULL,
  removed_chunks INTEGER NOT NULL,
  removed_manifests INTEGER NOT NULL,
  reclaimed_blobs INTEGER NOT NULL,
  detail TEXT NOT NULL
);
"""


def connect(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Readers pin a generation for the whole duration of a long report while
    # concurrent ingests/migrations keep writing; WAL allows both at once.
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA busy_timeout=30000')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript(SCHEMA)
    return db
