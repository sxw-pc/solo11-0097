"""Simulated physical label printer (PRN-1) and verifier (SCAN-1).

Both devices keep their *own* append-only durable journals on the local
filesystem. The journals are outside SQLite, so a database rollback can never
make an already printed sheet disappear. Every record is hash-chained
(previous record hash included), making silent rewriting detectable.

No real hardware is involved: printed sheets are byte files on disk.
"""
import json
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def _append_jsonl(path, record):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    prev = ''
    if path.exists():
        last = path.read_bytes().rstrip().splitlines()
        if last:
            prev = json.loads(last[-1])['record_hash']
    record = dict(record)
    record['prev_hash'] = prev
    record['record_hash'] = sha256(
        json.dumps(record, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()
    with path.open('a', encoding='utf-8') as fh:
        fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + '\n')
    return record


def read_journal(path):
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def verify_chain(path):
    """Re-verify a device journal; returns (ok, first_broken_record_index)."""
    prev = ''
    for index, record in enumerate(read_journal(path)):
        stored = record.pop('record_hash')
        expected = sha256(
            json.dumps(record, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        record['record_hash'] = stored
        if record.get('prev_hash') != prev or stored != expected:
            return False, index
        prev = stored
    return True, None


class PrinterError(RuntimeError):
    def __init__(self, code, detail=''):
        super().__init__(code + (': ' + detail if detail else ''))
        self.code = code
        self.detail = detail


class Printer:
    """PRN-1 simulation.

    State on disk (all append-only / content-addressed):
      * command log: every command nonce received, before printing;
      * emission journal: every sheet that physically left the printer;
      * paper/: the actual printed sheet bytes.
    ACK is returned *after* physical emission. The registered jam fault
    injects an interruption after the paper is out but before the ACK.
    """

    def __init__(self, device_dir, printer_id='PRN-1',
                 jam_after_serial=None):
        self.dir = Path(device_dir) / printer_id
        self.id = printer_id
        self.jam_after_serial = jam_after_serial
        self.command_log = self.dir / 'commands.jsonl'
        self.journal = self.dir / 'emissions.jsonl'
        self.paper_dir = self.dir / 'paper'

    def _find_command(self, nonce):
        for record in read_journal(self.command_log):
            if record['nonce'] == nonce:
                return record
        return None

    def _find_emission(self, nonce):
        for record in read_journal(self.journal):
            if record['nonce'] == nonce:
                return record
        return None

    def print_label(self, *, nonce, serial, content_sha256, sheet_bytes):
        """Send a print command; returns the ACK.

        The command nonce makes re-delivery idempotent and non-replayable:
        the same nonce yields the same result without a second sheet, while a
        reused nonce with different content is rejected outright.
        """
        if not nonce:
            raise PrinterError('nonce_required')
        prior = self._find_command(nonce)
        if prior is not None:
            if prior['content_sha256'] != content_sha256 \
                    or prior['serial'] != serial:
                raise PrinterError('nonce_reuse_conflict', nonce)
            emitted = self._find_emission(nonce)
            if emitted is not None:
                return {'status': 'ack', 'nonce': nonce,
                        'duplicate_delivery': True,
                        'emission_id': emitted['record_hash']}
            # Command durably logged, sheet not emitted yet: the original
            # attempt died between receipt and printing.
            raise PrinterError('command_pending_no_emission', nonce)

        _append_jsonl(self.command_log, {
            'ts': utc_now(), 'device_id': self.id, 'event': 'command_received',
            'nonce': nonce, 'serial': serial,
            'content_sha256': content_sha256})

        # Physical emission happens first; the paper exists regardless of
        # what happens to the ACK afterwards.
        self.paper_dir.mkdir(parents=True, exist_ok=True)
        paper_path = self.paper_dir / (serial + '.lbl')
        if paper_path.exists():
            raise PrinterError('paper_slot_collision', serial)
        paper_path.write_bytes(bytes(sheet_bytes))
        emission = _append_jsonl(self.journal, {
            'ts': utc_now(), 'device_id': self.id, 'event': 'sheet_emitted',
            'nonce': nonce, 'serial': serial,
            'content_sha256': content_sha256,
            'paper_path': str(paper_path),
            'paper_sha256': sha256(bytes(sheet_bytes)).hexdigest()})

        if self.jam_after_serial == serial:
            # Fault injection point: paper already out, ACK never sent.
            raise PrinterError('jam_after_emission_before_ack', serial)

        _append_jsonl(self.journal, {
            'ts': utc_now(), 'device_id': self.id, 'event': 'ack_sent',
            'nonce': nonce, 'serial': serial})
        return {'status': 'ack', 'nonce': nonce,
                'duplicate_delivery': False,
                'emission_id': emission['record_hash']}

    def emitted_serials(self):
        return [r for r in read_journal(self.journal)
                if r['event'] == 'sheet_emitted']

    def find_emission(self, serial):
        for record in reversed(self.emitted_serials()):
            if record['serial'] == serial:
                return record
        return None

    def paper_bytes(self, serial):
        emission = self.find_emission(serial)
        if emission is None:
            return None
        path = Path(emission['paper_path'])
        return path.read_bytes() if path.exists() else None

    @staticmethod
    def new_nonce():
        return 'N-' + uuid.uuid4().hex


class ScanRejection(RuntimeError):
    def __init__(self, code, detail=''):
        super().__init__(code + (': ' + detail if detail else ''))
        self.code = code
        self.detail = detail


class Scanner:
    """SCAN-1 simulation with its own durable scan journal."""

    def __init__(self, device_dir, scanner_id='SCAN-1'):
        self.dir = Path(device_dir) / scanner_id
        self.id = scanner_id
        self.journal = self.dir / 'scans.jsonl'

    def read_sheet(self, *, serial_on_paper, sheet_bytes, expected_box_id):
        """Read back a physical sheet attached to a business box.

        Only succeeds when the paper is intact, its digest matches, and the
        box printed on the label is the box physically presenting it.
        """
        from .sheet import parse_sheet
        record = {'ts': utc_now(), 'device_id': self.id,
                  'event': 'scan_attempt', 'expected_box': expected_box_id,
                  'serial_on_paper': serial_on_paper}
        try:
            parsed = parse_sheet(sheet_bytes)
            record['content_sha256'] = parsed['content_sha256']
            record['printed_sha256'] = parsed['printed_sha256']
            if not parsed['digest_valid']:
                raise ScanRejection('sheet_digest_mismatch', serial_on_paper)
            if parsed['serial'] != serial_on_paper:
                raise ScanRejection('serial_identity_mismatch',
                                    f'{parsed["serial"]}!={serial_on_paper}')
            if parsed['box_id'] != expected_box_id:
                raise ScanRejection('wrong_box',
                                    f'label box {parsed["box_id"]} presented on {expected_box_id}')
            record['event'] = 'scan_ok'
            record['box_id'] = parsed['box_id']
            record['mode'] = parsed['mode']
            record['status'] = 'ok'
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            record['event'] = 'scan_rejected'
            record['status'] = 'rejected'
            record['reason'] = 'unreadable_sheet:' + type(exc).__name__
            _append_jsonl(self.journal, record)
            raise ScanRejection('unreadable_sheet', str(exc)) from exc
        except ScanRejection as exc:
            record['event'] = 'scan_rejected'
            record['status'] = 'rejected'
            record['reason'] = exc.code
            _append_jsonl(self.journal, record)
            raise
        saved = _append_jsonl(self.journal, record)
        return {'status': 'ok', 'serial': parsed['serial'],
                'box_id': parsed['box_id'], 'mode': parsed['mode'],
                'content_sha256': parsed['content_sha256'],
                'scan_id': saved['record_hash']}

    def scans(self):
        return read_journal(self.journal)
