"""Freeze an evidence-export contract; no release package is produced."""
import json
from hashlib import sha256
from pathlib import Path
from .store import connect


def register(db_path, contract_path):
    raw=Path(contract_path).read_bytes()
    contract=json.loads(raw)
    db=connect(db_path)
    db.executescript('''CREATE TABLE IF NOT EXISTS export_case(
      id TEXT PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES batch(id),
      contract_sha256 TEXT NOT NULL, contract_json TEXT NOT NULL,
      source_digest TEXT NOT NULL
    );''')
    if not db.execute('SELECT 1 FROM batch WHERE id=?',(contract['batch_id'],)).fetchone():
        raise ValueError('unknown_cold_batch')
    sources=[r['hash'] for r in db.execute('SELECT hash FROM source_file ORDER BY hash')]
    if not sources:
        raise ValueError('missing_source')
    digest=sha256('|'.join(sources).encode()).hexdigest()
    with db:
        db.execute('INSERT INTO export_case VALUES (?,?,?,?,?)',
                   (contract['case_id'],contract['batch_id'],sha256(raw).hexdigest(),raw.decode(),digest))
    db.close()
    return contract['case_id']
