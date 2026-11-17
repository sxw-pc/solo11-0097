"""Intake of physical shipment label production; no labels are printed."""
import json
from hashlib import sha256
from pathlib import Path
from .store import connect


def register(db_path, contract_path):
    raw = Path(contract_path).read_bytes()
    contract = json.loads(raw)
    db = connect(db_path)
    db.executescript('''CREATE TABLE IF NOT EXISTS label_case(
      id TEXT PRIMARY KEY, contract_sha256 TEXT NOT NULL,
      contract_json TEXT NOT NULL, box_digest TEXT NOT NULL
    );''')
    boxes = []
    for item in contract['labels']:
        row = db.execute('SELECT * FROM box WHERE id=?',(item['box_id'],)).fetchone()
        if row is None:
            raise ValueError('unknown_box')
        boxes.append(dict(row))
    digest = sha256(json.dumps(boxes, sort_keys=True).encode()).hexdigest()
    with db:
        db.execute('INSERT INTO label_case VALUES (?,?,?,?)',
                   (contract['case_id'],sha256(raw).hexdigest(),raw.decode(),digest))
    db.close()
    return contract['case_id']
