"""Freeze manufacturer seal ledgers and observed seal scans; no authenticity verdict."""
import json
from hashlib import sha256
from pathlib import Path
from .store import connect


def register(db_path, contract_path):
    raw = Path(contract_path).read_bytes()
    contract = json.loads(raw)
    db = connect(db_path)
    db.executescript('''CREATE TABLE IF NOT EXISTS seal_case(
      id TEXT PRIMARY KEY, serial TEXT NOT NULL, contract_sha256 TEXT NOT NULL,
      contract_json TEXT NOT NULL, observed_digest TEXT NOT NULL
    );''')
    observed=[]
    for row in db.execute("SELECT id,box_id,source_id,hash,payload FROM raw_event WHERE kind IN ('open','reseal') ORDER BY id"):
        if json.loads(row['payload']).get('seal')==contract['serial']:
            observed.append(dict(row))
    if len({r['box_id'] for r in observed})<2:
        raise ValueError('missing_duplicate_physical_seal')
    digest=sha256(json.dumps(observed,sort_keys=True).encode()).hexdigest()
    with db:
        db.execute('INSERT INTO seal_case VALUES (?,?,?,?,?)',
                   (contract['case_id'],contract['serial'],sha256(raw).hexdigest(),raw.decode(),digest))
    db.close()
    return contract['case_id']
