r"""Physical box label issuance, provenance ledger and recovery workflow.

The label lifecycle is::

    reserved -> printed -> applied
        |          |          |
        +-> quarantined       +-> revoked (explicit correction only)
                   \---------->/  revoked -> reprint (new serial)

Invariants enforced by the database and the state machine:

* a serial is reserved transactionally and can never be issued twice;
* at most one current valid label exists per box (partial unique index);
* ``label_event`` is strictly append-only (SQLite triggers block rewrite);
* the printer/scanner journals live outside SQLite, so a DB rollback never
  makes physical paper vanish — recovery always starts from device evidence;
* printed bytes are pinned to a contract version via a source digest, so a
  recipient-contract revision can never be impersonated by old paper.
"""
import json
import sqlite3
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from .devices import (Printer, Scanner, PrinterError, ScanRejection,
                      read_journal, verify_chain)
from .sheet import MODES, TEMPLATE_VERSION, binding_digest, render_sheet
from .store import connect

LABEL_SCHEMA = '''
CREATE TABLE IF NOT EXISTS label_contract_version(
  case_id TEXT NOT NULL, version INTEGER NOT NULL,
  contract_sha256 TEXT NOT NULL, contract_json TEXT NOT NULL,
  box_digest TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY(case_id, version));
CREATE TABLE IF NOT EXISTS label_job(
  job_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, mode TEXT NOT NULL,
  contract_version INTEGER NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
  UNIQUE(case_id, mode));
CREATE TABLE IF NOT EXISTS serial_ledger(
  serial TEXT PRIMARY KEY, case_id TEXT NOT NULL, box_id TEXT NOT NULL,
  job_id TEXT NOT NULL, mode TEXT NOT NULL, contract_version INTEGER NOT NULL,
  template_version TEXT NOT NULL, content_sha256 TEXT NOT NULL,
  source_digest TEXT NOT NULL, sheet_bytes BLOB NOT NULL,
  nonce TEXT, state TEXT NOT NULL, replaces_serial TEXT,
  replaced_by_serial TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ux_serial_nonce ON serial_ledger(nonce)
  WHERE nonce IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_box_current_label ON serial_ledger(box_id)
  WHERE state IN ('reserved','printed','applied');
CREATE TABLE IF NOT EXISTS label_event(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, serial TEXT,
  box_id TEXT, job_id TEXT, event TEXT NOT NULL, source TEXT NOT NULL,
  detail TEXT NOT NULL, evidence_ref TEXT, prev_hash TEXT NOT NULL,
  event_hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS label_event_no_delete BEFORE DELETE ON label_event
  BEGIN SELECT RAISE(ABORT,'label_event_append_only'); END;
CREATE TRIGGER IF NOT EXISTS label_event_no_update BEFORE UPDATE ON label_event
  BEGIN SELECT RAISE(ABORT,'label_event_append_only'); END;
'''


def _now():
    return datetime.now(timezone.utc).isoformat()


def _db(path):
    db = sqlite3.connect(str(path), timeout=30)
    db.row_factory = sqlite3.Row
    db.isolation_level = None
    db.executescript(LABEL_SCHEMA)
    return db


def _event(db, *, event, source, serial=None, box_id=None, job_id=None,
           detail=None, evidence_ref=None):
    prev = db.execute('SELECT event_hash FROM label_event ORDER BY id DESC LIMIT 1'
                      ).fetchone()
    prev_hash = prev['event_hash'] if prev else ''
    body = {'ts': _now(), 'serial': serial, 'box_id': box_id, 'job_id': job_id,
            'event': event, 'source': source,
            'detail': json.dumps(detail if detail is not None else {},
                                 sort_keys=True, ensure_ascii=False),
            'evidence_ref': evidence_ref, 'prev_hash': prev_hash}
    body['event_hash'] = sha256(
        json.dumps(body, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()
    db.execute('''INSERT INTO label_event(ts,serial,box_id,job_id,event,source,
                 detail,evidence_ref,prev_hash,event_hash)
                 VALUES(:ts,:serial,:box_id,:job_id,:event,:source,:detail,
                 :evidence_ref,:prev_hash,:event_hash)''', body)
    return body['event_hash']


# --------------------------------------------------------------------------- #
# Contract registration and revision
# --------------------------------------------------------------------------- #

def register(db_path, contract_path):
    """Freeze the authorised label contract (original seed behaviour)."""
    raw = Path(contract_path).read_bytes()
    contract = json.loads(raw)
    db = connect(db_path)
    db.executescript('''CREATE TABLE IF NOT EXISTS label_case(
      id TEXT PRIMARY KEY, contract_sha256 TEXT NOT NULL,
      contract_json TEXT NOT NULL, box_digest TEXT NOT NULL);''')
    boxes = []
    for item in contract['labels']:
        row = db.execute('SELECT * FROM box WHERE id=?',
                         (item['box_id'],)).fetchone()
        if row is None:
            raise ValueError('unknown_box')
        boxes.append(dict(row))
    digest = sha256(json.dumps(boxes, sort_keys=True).encode()).hexdigest()
    with db:
        db.execute('INSERT OR IGNORE INTO label_case VALUES (?,?,?,?)',
                   (contract['case_id'], sha256(raw).hexdigest(),
                    raw.decode(), digest))
    db.close()
    wdb = _db(db_path)
    try:
        wdb.execute('BEGIN IMMEDIATE')
        same = wdb.execute(
            'SELECT version FROM label_contract_version WHERE case_id=? '
            'AND contract_sha256=?',
            (contract['case_id'], sha256(raw).hexdigest())).fetchone()
        if same is not None:
            wdb.commit()
            return contract['case_id']
        existing = wdb.execute(
            'SELECT version FROM label_contract_version WHERE case_id=? '
            'ORDER BY version DESC LIMIT 1', (contract['case_id'],)).fetchone()
        version = (existing['version'] + 1) if existing else 1
        wdb.execute('INSERT INTO label_contract_version VALUES (?,?,?,?,?,?)',
                   (contract['case_id'], version, sha256(raw).hexdigest(),
                    raw.decode(), digest, _now()))
        wdb.commit()
    except Exception:
        wdb.rollback()
        raise
    finally:
        wdb.close()
    return contract['case_id']


def revise_contract(db_path, contract_path):
    """Register a new recipient-contract version for the same frozen case.

    Old sheets stay historically valid evidence but their source digest no
    longer matches the current binding, so they can never be applied as if
    they were produced under the new contract.
    """
    raw = Path(contract_path).read_bytes()
    contract = json.loads(raw)
    db = connect(db_path)
    case = db.execute('SELECT * FROM label_case WHERE id=?',
                      (contract['case_id'],)).fetchone()
    if case is None:
        db.close()
        raise ValueError('unknown_case')
    old = json.loads(case['contract_json'])
    if {x['box_id'] for x in old['labels']} != \
            {x['box_id'] for x in contract['labels']}:
        db.close()
        raise ValueError('box_set_mismatch')
    if sha256(raw).hexdigest() == case['contract_sha256']:
        db.close()
        raise ValueError('contract_unchanged')
    boxes = [dict(r) for r in db.execute(
        'SELECT * FROM box WHERE id IN (%s)' %
        ','.join('?' * len(contract['labels'])),
        [x['box_id'] for x in contract['labels']])]
    box_digest = sha256(json.dumps(boxes, sort_keys=True).encode()).hexdigest()
    db.close()
    wdb = _db(db_path)
    try:
        wdb.execute('BEGIN IMMEDIATE')
        version = wdb.execute(
            'SELECT version+1 AS v FROM label_contract_version WHERE case_id=? '
            'ORDER BY version DESC LIMIT 1', (contract['case_id'],)).fetchone()['v']
        wdb.execute('INSERT INTO label_contract_version VALUES (?,?,?,?,?,?)',
                    (contract['case_id'], version, sha256(raw).hexdigest(),
                     raw.decode(), box_digest, _now()))
        _event(wdb, event='contract_revised', source='operator',
               box_id=None,
               detail={'version': version,
                       'contract_sha256': sha256(raw).hexdigest()})
        wdb.commit()
        return version
    except Exception:
        wdb.rollback()
        raise
    finally:
        wdb.close()


def _latest_contract(db, case_id):
    row = db.execute(
        'SELECT * FROM label_contract_version WHERE case_id=? '
        'ORDER BY version DESC LIMIT 1', (case_id,)).fetchone()
    if row is None:
        raise ValueError('unknown_case')
    return dict(row)


def _contract_item(contract, box_id):
    for item in json.loads(contract['contract_json'])['labels']:
        if item['box_id'] == box_id:
            return item
    raise ValueError('box_not_in_contract')


def current_binding(db, case_id, box_id):
    contract = _latest_contract(db, case_id)
    item = _contract_item(contract, box_id)
    return binding_digest(case_id=case_id,
                          contract_sha256=contract['contract_sha256'],
                          box_id=box_id, recipient=item['recipient'],
                          opaque_id=item['opaque_id'])


# --------------------------------------------------------------------------- #
# Device construction (jam fault comes from the frozen contract)
# --------------------------------------------------------------------------- #

def build_devices(db_path, device_dir, case_id):
    db = connect(db_path)
    contract = json.loads(_latest_contract(db, case_id)['contract_json'])
    db.close()
    jam = contract.get('jam_injection') or {}
    jam_serial = jam.get('after_serial') \
        if jam.get('point') == 'after_physical_print_before_ack' else None
    printer_id = contract['printer']['id']
    scanner_id = contract['verifier']['id']
    return (Printer(device_dir, printer_id, jam_after_serial=jam_serial),
            Scanner(device_dir, scanner_id))


# --------------------------------------------------------------------------- #
# Job, reservation and rendering
# --------------------------------------------------------------------------- #

def _open_job_locked(db, case_id, mode):
    contract = _latest_contract(db, case_id)
    job_id = sha256(
        (case_id + '|' + mode + '|' + str(contract['version'])).encode()
    ).hexdigest()[:16]
    db.execute('INSERT OR IGNORE INTO label_job VALUES (?,?,?,?,?,?)',
               (job_id, case_id, mode, contract['version'], 'open', _now()))
    _event(db, event='job_opened', source='ledger', job_id=job_id,
           detail={'case_id': case_id, 'mode': mode,
                   'contract_version': contract['version']})
    return job_id


def open_job(db_path, case_id, mode):
    if mode not in MODES:
        raise ValueError('unknown_mode')
    db = _db(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        clash = db.execute(
            "SELECT mode FROM label_job WHERE case_id=? AND mode<>? AND status='open'",
            (case_id, mode)).fetchone()
        if clash is not None:
            raise ValueError('another_mode_already_active:' + clash['mode'])
        job_id = _open_job_locked(db, case_id, mode)
        db.commit()
        return job_id
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def close_job(db_path, job_id):
    db = _db(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM label_job WHERE job_id=?',
                         (job_id,)).fetchone()
        if row is None:
            raise ValueError('unknown_job')
        db.execute("UPDATE label_job SET status='closed' WHERE job_id=?",
                   (job_id,))
        _event(db, event='job_closed', source='ledger', job_id=job_id,
               detail={'mode': row['mode']})
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _mint_serial(db, case_id):
    """Next free serial, skipping numbers the contract freezes for boxes."""
    used = set()
    for r in db.execute('SELECT serial FROM serial_ledger WHERE case_id=?',
                        (case_id,)).fetchall():
        used.add(r['serial'])
    for r in db.execute(
            "SELECT contract_json FROM label_contract_version WHERE case_id=? "
            "ORDER BY version", (case_id,)).fetchall():
        for item in json.loads(r['contract_json'])['labels']:
            used.add(item['serial'])
    highest = max((int(s.split('-')[1]) for s in used
                   if s.startswith('SER-') and s.split('-')[1].isdigit()),
                  default=0)
    return 'SER-%04d' % (highest + 1)


def reserve(db_path, case_id, box_id, mode, *, serial=None, replaces=None,
            job_id=None):
    """Reserve a never-used serial and pin the rendered bytes atomically."""
    if mode not in MODES:
        raise ValueError('unknown_mode')
    db = _db(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        contract = _latest_contract(db, case_id)
        item = _contract_item(contract, box_id)
        if job_id is None:
            job_id = _open_job_locked(db, case_id, mode)
        if replaces is not None:
            old = db.execute('SELECT * FROM serial_ledger WHERE serial=?',
                             (replaces,)).fetchone()
            if old is None:
                raise ValueError('unknown_replaced_serial')
            old = dict(old)
            if old['state'] != 'revoked':
                raise ValueError('can_only_replace_revoked_serial')
            if old['box_id'] != box_id:
                raise ValueError('replacement_box_mismatch')
            serial = serial or _mint_serial(db, case_id)
        else:
            clash = db.execute(
                "SELECT serial FROM serial_ledger WHERE box_id=? AND state IN "
                "('reserved','printed','applied')", (box_id,)).fetchone()
            if clash is not None:
                raise ValueError('box_already_has_active_label:' + clash['serial'])
            serial = serial or item['serial']
        if db.execute('SELECT 1 FROM serial_ledger WHERE serial=?',
                      (serial,)).fetchone():
            raise ValueError('serial_already_used:' + serial)
        sheet = render_sheet(case_id=case_id,
                             contract_sha256=contract['contract_sha256'],
                             box_id=box_id, serial=serial, mode=mode,
                             recipient=item['recipient'],
                             opaque_id=item['opaque_id'])
        ts = _now()
        db.execute('''INSERT INTO serial_ledger(serial,case_id,box_id,job_id,
                     mode,contract_version,template_version,content_sha256,
                     source_digest,sheet_bytes,nonce,state,replaces_serial,
                     replaced_by_serial,created_at,updated_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                   (serial, case_id, box_id, job_id, mode, contract['version'],
                    TEMPLATE_VERSION, sheet['content_sha256'],
                    sheet['source_digest'],
                    sqlite3.Binary(sheet['sheet_bytes']), None, 'reserved',
                    replaces, None, ts, ts))
        if replaces is not None:
            db.execute('UPDATE serial_ledger SET replaced_by_serial=?,updated_at=? '
                       'WHERE serial=?', (serial, ts, replaces))
        _event(db, event='reserved', source='ledger', serial=serial,
               box_id=box_id, job_id=job_id,
               detail={'mode': mode, 'contract_version': contract['version'],
                       'content_sha256': sheet['content_sha256'],
                       'source_digest': sheet['source_digest'],
                       'replaces': replaces})
        db.commit()
        return {'serial': serial, **sheet}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _ledger(db, serial):
    row = db.execute('SELECT * FROM serial_ledger WHERE serial=?',
                     (serial,)).fetchone()
    if row is None:
        raise ValueError('unknown_serial:' + serial)
    return dict(row)


# --------------------------------------------------------------------------- #
# Printing, ACK, late-ACK reconciliation and command re-delivery
# --------------------------------------------------------------------------- #

def send_print(db_path, serial, device_dir, *, simulate_lost_ack=False):
    """Send the print command. ACK only proves command delivery."""
    db = _db(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        row = _ledger(db, serial)
        if row['state'] not in ('reserved',):
            raise ValueError('not_printable_state:' + row['state'])
        nonce = row['nonce'] or Printer.new_nonce()
        printer, _ = build_devices(db_path, device_dir, row['case_id'])
        sheet_bytes = bytes(row['sheet_bytes'])
        _event(db, event='print_command_sent', source='ledger', serial=serial,
               box_id=row['box_id'], job_id=row['job_id'],
               detail={'nonce': nonce, 'printer': printer.id,
                       'content_sha256': row['content_sha256']},
               evidence_ref=nonce)
        db.execute('UPDATE serial_ledger SET nonce=?,updated_at=? WHERE serial=?',
                   (nonce, _now(), serial))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    try:
        ack = printer.print_label(nonce=nonce, serial=serial,
                                  content_sha256=row['content_sha256'],
                                  sheet_bytes=sheet_bytes)
    except PrinterError as exc:
        if exc.code == 'jam_after_emission_before_ack':
            _record_jam(db_path, serial, nonce, printer)
            return {'status': 'jammed_after_emission', 'serial': serial,
                    'nonce': nonce}
        raise
    if simulate_lost_ack:
        # The printer durably emitted and acked, but the worker never heard.
        _append_simple(db_path, serial, row, 'print_ack_lost', nonce,
                       ack.get('emission_id'))
        return {'status': 'ack_lost', 'serial': serial, 'nonce': nonce}
    _mark_printed(db_path, serial, nonce, ack['emission_id'], duplicate=False)
    return {'status': 'printed', 'serial': serial, 'nonce': nonce,
            'duplicate_delivery': ack['duplicate_delivery']}


def _append_simple(db_path, serial, row, event, nonce, evidence_ref, detail=None):
    db = _db(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        _event(db, event=event, source='printer-journal', serial=serial,
               box_id=row['box_id'], job_id=row['job_id'],
               detail=detail or {'nonce': nonce}, evidence_ref=evidence_ref)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _record_jam(db_path, serial, nonce, printer):
    db = _db(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        row = _ledger(db, serial)
        emission = printer.find_emission(serial)
        # The paper physically exists; the ledger row must NOT be removed.
        _event(db, event='print_jam', source='printer-journal', serial=serial,
               box_id=row['box_id'], job_id=row['job_id'],
               detail={'nonce': nonce, 'paper_exists': emission is not None,
                       'paper_sha256': emission and emission['paper_sha256']},
               evidence_ref=emission['record_hash'] if emission else nonce)
        db.commit()
    finally:
        db.close()


def _mark_printed(db_path, serial, nonce, emission_id, *, duplicate):
    db = _db(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        row = _ledger(db, serial)
        if row['state'] == 'printed':
            _event(db, event='print_ack_duplicate', source='printer-journal',
                   serial=serial, box_id=row['box_id'], job_id=row['job_id'],
                   detail={'nonce': nonce}, evidence_ref=emission_id)
        else:
            db.execute("UPDATE serial_ledger SET state='printed',updated_at=? "
                       'WHERE serial=?', (_now(), serial))
            _event(db, event='print_ack', source='printer-journal',
                   serial=serial, box_id=row['box_id'], job_id=row['job_id'],
                   detail={'nonce': nonce, 'duplicate_delivery': duplicate},
                   evidence_ref=emission_id)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def reconcile_print(db_path, serial, device_dir):
    """Converge ledger state from the immutable printer journal.

    ACK loss, late ACK and jam recovery all start here: device evidence is
    authoritative about whether paper physically exists.
    """
    db = _db(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        row = _ledger(db, serial)
        printer, _ = build_devices(db_path, device_dir, row['case_id'])
        emission = printer.find_emission(serial)
        command = next((c for c in read_journal(printer.command_log)
                        if c['nonce'] == row['nonce']), None)
        if emission is not None:
            if row['state'] == 'reserved':
                db.execute("UPDATE serial_ledger SET state='printed',updated_at=? "
                           'WHERE serial=?', (_now(), serial))
            _event(db, event='emission_confirmed', source='printer-journal',
                   serial=serial, box_id=row['box_id'], job_id=row['job_id'],
                   detail={'nonce': row['nonce'],
                           'paper_sha256': emission['paper_sha256'],
                           'paper_path': emission['paper_path']},
                   evidence_ref=emission['record_hash'])
            db.commit()
            return {'status': 'emission_confirmed', 'serial': serial,
                    'paper_sha256': emission['paper_sha256']}
        if command is not None:
            _event(db, event='print_command_only_no_paper', source='printer-journal',
                   serial=serial, box_id=row['box_id'], job_id=row['job_id'],
                   detail={'nonce': row['nonce']},
                   evidence_ref=command['record_hash'])
            db.commit()
            return {'status': 'command_without_emission', 'serial': serial}
        db.commit()
        return {'status': 'no_command_evidence', 'serial': serial}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def redeliver_command(db_path, serial, device_dir):
    """Re-deliver the exact same command (same nonce). No second sheet."""
    db = connect(db_path)
    row = dict(db.execute('SELECT * FROM serial_ledger WHERE serial=?',
                          (serial,)).fetchone())
    db.close()
    if not row['nonce']:
        raise ValueError('no_command_to_redeliver')
    printer, _ = build_devices(db_path, device_dir, row['case_id'])
    before = len(printer.emitted_serials())
    ack = printer.print_label(nonce=row['nonce'], serial=serial,
                              content_sha256=row['content_sha256'],
                              sheet_bytes=bytes(row['sheet_bytes']))
    after = len(printer.emitted_serials())
    if ack['duplicate_delivery'] and row['state'] == 'reserved':
        _mark_printed(db_path, serial, row['nonce'],
                      ack['emission_id'], duplicate=True)
    return {'ack': ack, 'emissions_added': after - before}


# --------------------------------------------------------------------------- #
# Scan verification and application
# --------------------------------------------------------------------------- #

def apply_label(db_path, serial, device_dir, presented_box, sheet_bytes=None):
    """Apply a physical label after SCAN-1 read-back on the correct box."""
    db = _db(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        row = _ledger(db, serial)
        if row['state'] == 'revoked':
            raise ScanRejection('serial_revoked', serial)
        if row['state'] == 'quarantined':
            raise ScanRejection('serial_quarantined', serial)
        binding_now = current_binding(db, row['case_id'], row['box_id'])
        if binding_now != row['source_digest']:
            raise ScanRejection('binding_stale_contract_revised', serial)
        printer, scanner = build_devices(db_path, device_dir, row['case_id'])
        if sheet_bytes is None:
            sheet_bytes = printer.paper_bytes(serial)
        if sheet_bytes is None:
            raise ScanRejection('physical_paper_not_found', serial)
        try:
            result = scanner.read_sheet(serial_on_paper=serial,
                                        sheet_bytes=sheet_bytes,
                                        expected_box_id=presented_box)
        except ScanRejection as exc:
            _event(db, event='scan_rejected', source='scanner-journal',
                   serial=serial, box_id=presented_box, job_id=row['job_id'],
                   detail={'reason': exc.code, 'detail': exc.detail})
            db.commit()
            raise
        if result['content_sha256'] != row['content_sha256']:
            _event(db, event='scan_rejected', source='scanner-journal',
                   serial=serial, box_id=presented_box, job_id=row['job_id'],
                   detail={'reason': 'content_digest_mismatch'})
            db.commit()
            raise ScanRejection('content_digest_mismatch', serial)
        db.execute("UPDATE serial_ledger SET state='applied',updated_at=? "
                   'WHERE serial=?', (_now(), serial))
        _event(db, event='scan_accepted', source='scanner-journal',
               serial=serial, box_id=row['box_id'], job_id=row['job_id'],
               detail={'presented_box': presented_box,
                       'content_sha256': result['content_sha256'],
                       'mode': result['mode']},
               evidence_ref=result['scan_id'])
        db.commit()
        return {'status': 'applied', 'serial': serial, 'box_id': row['box_id'],
                'scan_id': result['scan_id']}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Destruction, revocation, quarantine and reprint
# --------------------------------------------------------------------------- #

def _transition(db, serial, new_state):
    db.execute('UPDATE serial_ledger SET state=?,updated_at=? WHERE serial=?',
               (new_state, _now(), serial))


def record_destruction(db_path, serial, evidence_note):
    """Register immutable destruction evidence for a physical sheet."""
    db = _db(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        row = _ledger(db, serial)
        already = db.execute(
            "SELECT 1 FROM label_event WHERE serial=? AND event='destruction_recorded'",
            (serial,)).fetchone()
        if already:
            raise ValueError('destruction_evidence_immutable')
        _event(db, event='destruction_recorded', source='operator',
               serial=serial, box_id=row['box_id'], job_id=row['job_id'],
               detail={'note': evidence_note,
                       'content_sha256': row['content_sha256']})
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def revoke(db_path, serial, reason, evidence_note=''):
    db = _db(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        row = _ledger(db, serial)
        if row['state'] == 'revoked':
            raise ValueError('already_revoked')
        _transition(db, serial, 'revoked')
        _event(db, event='revoked', source='operator', serial=serial,
               box_id=row['box_id'], job_id=row['job_id'],
               detail={'reason': reason, 'note': evidence_note,
                       'prior_state': row['state']})
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def quarantine(db_path, serial, reason):
    """Freeze a serial whose physical paper cannot be located. No auto retry."""
    db = _db(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        row = _ledger(db, serial)
        if row['state'] not in ('reserved', 'printed'):
            raise ValueError('cannot_quarantine_state:' + row['state'])
        _transition(db, serial, 'quarantined')
        _event(db, event='quarantined', source='operator', serial=serial,
               box_id=row['box_id'], job_id=row['job_id'],
               detail={'reason': reason})
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def resolve_quarantine(db_path, serial, decision, evidence_note):
    """Explicit human resolution; never automatic."""
    db = _db(db_path)
    try:
        db.execute('BEGIN IMMEDIATE')
        row = _ledger(db, serial)
        if row['state'] != 'quarantined':
            raise ValueError('not_quarantined')
        if decision == 'located_intact':
            _transition(db, serial, 'printed')
            _event(db, event='quarantine_released', source='operator',
                   serial=serial, box_id=row['box_id'], job_id=row['job_id'],
                   detail={'decision': decision, 'note': evidence_note})
        elif decision == 'confirmed_lost':
            # Inline the immutable destruction event: a second connection
            # could not take the write lock while this transaction holds it.
            _event(db, event='destruction_recorded', source='operator',
                   serial=serial, box_id=row['box_id'], job_id=row['job_id'],
                   detail={'note': 'quarantine:' + evidence_note,
                           'content_sha256': row['content_sha256']})
            _transition(db, serial, 'revoked')
            _event(db, event='revoked', source='operator', serial=serial,
                   box_id=row['box_id'], job_id=row['job_id'],
                   detail={'reason': 'quarantine_confirmed_lost',
                           'note': evidence_note})
        else:
            raise ValueError('unknown_quarantine_decision')
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def reprint(db_path, old_serial, device_dir, reason, *, auto_apply=False):
    """Voided serials are replaced by a brand-new serial and fresh paper."""
    db = connect(db_path)
    old = dict(db.execute('SELECT * FROM serial_ledger WHERE serial=?',
                          (old_serial,)).fetchone())
    if old['state'] != 'revoked':
        db.close()
        raise ValueError('reprint_requires_revoked_serial')
    if old['replaced_by_serial'] is not None:
        db.close()
        raise ValueError('serial_already_replaced:' + old['replaced_by_serial'])
    active = db.execute(
        "SELECT serial FROM serial_ledger WHERE box_id=? AND state IN "
        "('reserved','printed','applied')", (old['box_id'],)).fetchone()
    db.close()
    if active is not None:
        raise ValueError('box_already_has_active_label:' + active['serial'])
    new = reserve(db_path, old['case_id'], old['box_id'], old['mode'],
                  replaces=old_serial, job_id=old['job_id'])
    result = send_print(db_path, new['serial'], device_dir)
    if auto_apply:
        # A jam interrupts between emission and ACK; the physical paper still
        # exists, so converge from the printer journal before read-back.
        if result['status'] == 'jammed_after_emission':
            reconcile_print(db_path, new['serial'], device_dir)
        applied = apply_label(db_path, new['serial'], device_dir,
                              old['box_id'])
        result['apply'] = applied
    return {'old_serial': old_serial, 'new_serial': new['serial'],
            'print': result}


def recover_jam(db_path, serial, device_dir, disposition, evidence_note=''):
    """Three-way recovery for 'printed before ACK' interruptions."""
    recon = reconcile_print(db_path, serial, device_dir)
    if recon['status'] != 'emission_confirmed':
        raise ValueError('no_physical_emission_evidence')
    if disposition == 'paper_recoverable':
        # Same serial continues; the read-back proves the real paper.
        return apply_label(db_path, serial, device_dir,
                           _box_of(db_path, serial))
    if disposition == 'paper_destroyed':
        record_destruction(db_path, serial, evidence_note or 'jam: shredded')
        revoke(db_path, serial, 'physical_destruction_after_jam', evidence_note)
        return reprint(db_path, serial, device_dir,
                       'jam_destruction', auto_apply=True)
    if disposition == 'whereabouts_unknown':
        quarantine(db_path, serial, 'jam: paper fate unverifiable')
        return {'status': 'quarantined', 'serial': serial}
    raise ValueError('unknown_disposition')


def _box_of(db_path, serial):
    db = connect(db_path)
    box = db.execute('SELECT box_id FROM serial_ledger WHERE serial=?',
                     (serial,)).fetchone()['box_id']
    db.close()
    return box


# --------------------------------------------------------------------------- #
# End-to-end production and reports
# --------------------------------------------------------------------------- #

def produce(db_path, case_id, mode, device_dir, *, box_ids=None):
    """Run one authorised layout for the case; one mode per job."""
    job_id = open_job(db_path, case_id, mode)
    db = connect(db_path)
    contract = json.loads(_latest_contract(db, case_id)['contract_json'])
    db.close()
    targets = [i for i in contract['labels']
               if box_ids is None or i['box_id'] in box_ids]
    summary = []
    for item in targets:
        try:
            reserved = reserve(db_path, case_id, item['box_id'], mode,
                               serial=item['serial'], job_id=job_id)
            outcome = send_print(db_path, reserved['serial'], device_dir)
        except ValueError as exc:
            outcome = {'status': 'skipped', 'reason': str(exc)}
        summary.append(outcome)
    return {'job_id': job_id, 'mode': mode, 'boxes': summary}


def current_usable(db_path):
    db = connect(db_path)
    rows = db.execute(
        "SELECT box_id,serial,state,mode,content_sha256 FROM serial_ledger "
        "WHERE state IN ('reserved','printed','applied') ORDER BY box_id"
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


def build_report(db_path, device_dir):
    db = connect(db_path)
    db.executescript(LABEL_SCHEMA)
    case_rows = db.execute(
        'SELECT * FROM label_contract_version ORDER BY case_id,version').fetchall()
    cases = {}
    for row in case_rows:
        cases.setdefault(row['case_id'], []).append(dict(row))
    ledgers = [dict(r) for r in db.execute(
        'SELECT * FROM serial_ledger ORDER BY box_id,created_at')]
    events = [dict(r) for r in db.execute(
        'SELECT * FROM label_event ORDER BY id')]
    jobs = [dict(r) for r in db.execute('SELECT * FROM label_job ORDER BY rowid')]
    paper = []
    chains = {}
    for case_id in cases:
        printer, scanner = build_devices(db_path, device_dir, case_id)
        chains[printer.id] = {'journal': str(printer.journal),
                              'chain_ok': verify_chain(printer.journal)[0],
                              'commands': len(read_journal(printer.command_log)),
                              'emissions': len(printer.emitted_serials())}
        chains[scanner.id] = {'journal': str(scanner.journal),
                              'chain_ok': verify_chain(scanner.journal)[0],
                              'scans': len(scanner.scans())}
        for emission in printer.emitted_serials():
            paper.append({
                'case_id': case_id, 'serial': emission['serial'],
                'content_sha256': emission['content_sha256'],
                'paper_sha256': emission['paper_sha256'],
                'paper_path': emission['paper_path'],
                'paper_exists': Path(emission['paper_path']).exists(),
                'emission_record': emission['record_hash']})
    for ledger in ledgers:
        ledger['sheet_bytes_sha256'] = sha256(
            bytes(ledger.pop('sheet_bytes'))).hexdigest()
        ledger['binding_current'] = (
            current_binding(db, ledger['case_id'], ledger['box_id'])
            == ledger['source_digest'])
    for event in events:
        event['detail'] = json.loads(event['detail'])
    db.close()
    uncertain = [p for p in paper
                 if not any(l['serial'] == p['serial'] and
                            l['state'] in ('printed', 'applied')
                            for l in ledgers)]
    return {
        'generated_at': _now(),
        'contract_versions': cases,
        'jobs': jobs,
        'current_usable': current_usable(db_path),
        'serials': ledgers,
        'physical_paper': paper,
        'uncertain_or_voided_paper': uncertain,
        'events': events,
        'device_journals': chains,
        'replacement_chains': [
            {'serial': l['serial'], 'replaces': l['replaces_serial'],
             'replaced_by': l['replaced_by_serial']}
            for l in ledgers if l['replaces_serial'] or l['replaced_by_serial']]}


def report(db_path, device_dir, out_path):
    data = build_report(db_path, device_dir)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                   encoding='utf-8')
    lines = ['# 实体标签制发审计报告', '',
             '生成时间：' + data['generated_at'], '',
             '## 当前可用序列号（每箱至多一张有效标签）', '']
    if data['current_usable']:
        for row in data['current_usable']:
            lines.append(
                f"- 箱 {row['box_id']} → {row['serial']}（{row['state']}，"
                f"版式 {row['mode']}，摘要 {row['content_sha256'][:12]}…）")
    else:
        lines.append('- 无')
    lines += ['', '## 序列号台账（含全部状态与替换链）', '']
    for row in data['serials']:
        stale = '' if row['binding_current'] else '，⚠ 合同已改版绑定失效'
        chain = ''
        if row['replaces_serial']:
            chain = f"，补印自 {row['replaces_serial']}"
        lines.append(
            f"- {row['serial']}｜箱 {row['box_id']}｜{row['state']}｜"
            f"{row['mode']}｜合同v{row['contract_version']}{chain}{stale}")
    lines += ['', '## 实物纸片（所有曾出纸及不确定纸片）', '']
    for paper in data['physical_paper']:
        mark = '✓' if paper['paper_exists'] else '✗'
        lines.append(
            f"- {paper['serial']}｜出纸记录 {paper['emission_record'][:12]}…｜"
            f"纸片存在 {mark}｜{paper['paper_path']}")
    if data['uncertain_or_voided_paper']:
        lines += ['', '其中状态不确定或已作废的纸片：', '']
        for paper in data['uncertain_or_voided_paper']:
            lines.append(f"- {paper['serial']}（{paper['paper_sha256'][:12]}…）")
    lines += ['', '## 设备日志完整性', '']
    for device, info in data['device_journals'].items():
        lines.append(f"- {device}：哈希链 {'完整' if info['chain_ok'] else '被篡改'}")
    lines.append('')
    out.with_suffix('.md').write_text('\n'.join(lines), encoding='utf-8')
    return out
