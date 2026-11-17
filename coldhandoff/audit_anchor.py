"""Freeze raw source identities for an append-only audit checkpoint."""
import json
from hashlib import sha256
from pathlib import Path
from .store import connect


def register(db_path, contract_path):
    raw=Path(contract_path).read_bytes()
    contract=json.loads(raw)
    db=connect(db_path)
    db.executescript('''CREATE TABLE IF NOT EXISTS anchor_case(
      id TEXT PRIMARY KEY, contract_sha256 TEXT NOT NULL,
      contract_json TEXT NOT NULL, source_snapshot TEXT NOT NULL
    );''')
    rows=[{'id':r['id'],'hash':r['hash']} for r in db.execute('SELECT id,hash FROM source_file ORDER BY id')]
    if len(rows)<2:
        raise ValueError('needs_two_sources')
    with db:
        db.execute('INSERT INTO anchor_case VALUES (?,?,?,?)',
                   (contract['case_id'],sha256(raw).hexdigest(),raw.decode(),
                    json.dumps(rows,sort_keys=True)))
    db.close()
    return contract['case_id']
