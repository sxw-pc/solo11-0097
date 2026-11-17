"""Freeze source-file bytes for a storage migration; no compaction performed."""
import json
from hashlib import sha256
from pathlib import Path
from .store import connect


def register(db_path, contract_path):
    raw = Path(contract_path).read_bytes()
    contract = json.loads(raw)
    db = connect(db_path)
    db.executescript('''CREATE TABLE IF NOT EXISTS archive_case(
      id TEXT PRIMARY KEY, contract_sha256 TEXT NOT NULL,
      contract_json TEXT NOT NULL, source_digest TEXT NOT NULL
    );''')
    rows = [dict(r) for r in db.execute('SELECT id,hash,raw FROM source_file ORDER BY id')]
    if len(rows) < 2:
        raise ValueError('needs_multiple_source_files')
    snapshot = [{'id':r['id'],'hash':r['hash'],'bytes':len(r['raw']),
                 'raw_sha256':sha256(r['raw']).hexdigest()} for r in rows]
    digest = sha256(json.dumps(snapshot,sort_keys=True).encode()).hexdigest()
    with db:
        db.execute('INSERT INTO archive_case VALUES (?,?,?,?)',
                   (contract['case_id'],sha256(raw).hexdigest(),raw.decode(),digest))
    db.close()
    return contract['case_id']
