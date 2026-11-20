"""Tiered evidence-package export for external recipients.

Two frozen recipient contracts are supported:

* ``regulator_full``      - byte-faithful package: original source bytes,
                            original hashes and every internal object.
* ``partner_pseudonymous``- rebuilt package: box relationships, event order,
                            issue codes and the decision chain survive, but
                            the collector identity, original source paths,
                            raw BLOBs and any field that can re-identify the
                            private actor are transformed away.

Partner packages are *rebuilt from the original bytes* (nested payloads,
Base64 blobs, Markdown/JSON attachments, exception details and reference
keys are all transformed), so every altered object carries a freshly
computed export hash and never claims equality with the original source
SHA.  Original id/hash <-> export id/hash mappings and identity
pseudonyms are kept only in the local database; they never enter an
external package.

Publishing is staged and crash-resumable.  A package is only moved into
its final recipient directory after the internal leak scan passes, so a
staging directory containing private text can never be delivered.
"""
import base64
import binascii
import csv
import hashlib
import hmac
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .store import connect

REGULATOR = 'regulator_full'
PARTNER = 'partner_pseudonymous'
KNOWN_CONTRACTS = (REGULATOR, PARTNER)
DEFAULT_RECIPIENT = {REGULATOR: 'regulator-primary', PARTNER: 'partner-primary'}

# Identity-ish scalar keys are pseudonymized (stable recipient handle);
# BLOB-ish keys in BLOB_KEY_HINTS and contract drop fields are removed.
IDENTITY_KEY_HINTS = ('actor', 'operator', 'collector', 'recorder',
                      'inspector', 'captured_by', 'recorded_by')
BLOB_KEY_HINTS = ('raw_original_bytes', 'raw_bytes', 'raw_blob')
STAGED, CONFIRMED, FAILED = 'staged', 'confirmed', 'failed'


class ExportError(RuntimeError):
    """Base class for export failures."""


class FrozenDigestMismatch(ExportError):
    """Live sources no longer match the frozen export case."""


class LeakDetected(ExportError):
    """Forbidden private text was found in an external package."""


def _now():
    return datetime.now(timezone.utc).isoformat()


def _sha256(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def _source_digest(db):
    hashes = [r['hash'] for r in db.execute('SELECT hash FROM source_file ORDER BY hash')]
    if not hashes:
        raise ExportError('missing_source')
    return _sha256('|'.join(hashes))


# ---------------------------------------------------------------------------
# Contract registration and pseudonym keys
# ---------------------------------------------------------------------------

def register(db_path, contract_path):
    """Freeze an evidence-export contract; no release package is produced.

    A case id is immutable: re-registering the same id after the sources or
    contract changed is refused.  Re-freeze changed evidence under a new
    case id (i.e. a new authorized contract), which starts a new package
    lineage; previously delivered packages and private mappings are never
    overwritten.
    """
    raw = Path(contract_path).read_bytes()
    contract = json.loads(raw)
    db = connect(db_path)
    db.executescript('''CREATE TABLE IF NOT EXISTS export_case(
      id TEXT PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES batch(id),
      contract_sha256 TEXT NOT NULL, contract_json TEXT NOT NULL,
      source_digest TEXT NOT NULL
    );''')
    if not db.execute('SELECT 1 FROM batch WHERE id=?', (contract['batch_id'],)).fetchone():
        raise ValueError('unknown_cold_batch')
    digest = _source_digest(db)
    prior = db.execute('SELECT * FROM export_case WHERE id=?',
                       (contract['case_id'],)).fetchone()
    if prior:
        if prior['source_digest'] != digest or prior['contract_sha256'] != _sha256(raw):
            raise FrozenDigestMismatch(
                'case %s is frozen; re-freeze changed evidence under a new case id'
                % contract['case_id'])
        db.close()
        return contract['case_id']
    with db:
        db.execute('INSERT INTO export_case VALUES (?,?,?,?,?)',
                   (contract['case_id'], contract['batch_id'],
                    _sha256(raw), raw.decode(), digest))
    db.close()
    return contract['case_id']


def rotate_key(db_path, key_id=None):
    """Rotate the partner pseudonym key.

    Already delivered packages keep their original ``key_id`` and stay
    verifiable; new packages use the fresh salt and therefore derive
    fresh, unlinkable pseudonyms.
    """
    db = connect(db_path)
    db.execute('BEGIN IMMEDIATE')
    closed = False
    try:
        previous = db.execute(
            'SELECT key_id FROM pseudonym_key ORDER BY created_at DESC LIMIT 1').fetchone()
        if key_id is None:
            key_id = 'synthetic-key-%d' % (
                db.execute('SELECT count(*) FROM pseudonym_key').fetchone()[0] + 1)
        salt = os.urandom(32)
        db.execute('INSERT INTO pseudonym_key(key_id,salt,created_at,rotated_from) '
                   'VALUES (?,?,?,?)',
                   (key_id, salt, _now(), previous['key_id'] if previous else None))
        db.commit(); db.close(); closed = True
        return key_id
    finally:
        if not closed:
            db.rollback(); db.close()


def _latest_key_id(db):
    row = db.execute('SELECT key_id FROM pseudonym_key ORDER BY created_at DESC LIMIT 1').fetchone()
    if row:
        return row['key_id']
    return _create_key(db)


def _create_key(db):
    key_id = 'synthetic-key-%d' % (
        db.execute('SELECT count(*) FROM pseudonym_key').fetchone()[0] + 1)
    db.execute('INSERT INTO pseudonym_key(key_id,salt,created_at,rotated_from) VALUES (?,?,?,?)',
               (key_id, os.urandom(32), _now(), None))
    return key_id


# ---------------------------------------------------------------------------
# Partner scrubbing: rebuild a restricted view from the original bytes
# ---------------------------------------------------------------------------

class Scrubber:
    """Recursive, recipient-bound transformer of the private evidence."""

    def __init__(self, secret, tokens, original_paths, drop_fields):
        self._secret = secret
        self.tokens = sorted(set(tokens))
        self.paths = sorted(set(original_paths), key=len, reverse=True)
        self.drop_fields = set(drop_fields)
        self.pseudonyms = {}
        # Binds rebuilt bytes (and their export hash) to this recipient/key
        # without exposing either the salt or the original source hash.
        self.source_binding = hmac.new(
            secret, b'restricted-source-binding', hashlib.sha256).hexdigest()[:16]

    def pseudonym(self, token):
        if token not in self.pseudonyms:
            digest = hmac.new(self._secret, ('pseudonym:' + token).encode(),
                              hashlib.sha256).hexdigest()[:12].upper()
            self.pseudonyms[token] = 'PN-' + digest
        return self.pseudonyms[token]

    def _is_drop_key(self, key):
        k = str(key).lower()
        if k in self.drop_fields:
            return True
        # Raw BLOB holders are removed outright; they carry original bytes.
        if any(h in k for h in BLOB_KEY_HINTS):
            return True
        # Identity-ish scalar fields are pseudonymized (not deleted) so the
        # recipient still sees a stable actor handle inside the chain.
        return False

    def _is_identity_key(self, key):
        k = str(key).lower()
        return k in ('actor', 'actor_name') or any(h in k for h in IDENTITY_KEY_HINTS)

    @staticmethod
    def _looks_like_b64(s):
        if len(s) < 16 or len(s) % 4:
            return False
        try:
            base64.b64decode(s, validate=True)
        except (binascii.Error, ValueError):
            return False
        return True

    def _scrub_b64(self, s):
        """Decode -> scrub raw bytes -> re-encode so BLOBs cannot hide text."""
        decoded = base64.b64decode(s)
        cleaned = self._scrub_bytes(decoded)
        return base64.b64encode(cleaned).decode('ascii')

    def _scrub_bytes(self, data):
        for token in self.tokens:
            data = data.replace(token.encode('utf-8'),
                                self.pseudonym(token).encode('utf-8'))
        for path in self.paths:
            data = data.replace(path.encode('utf-8'), b'REDACTED-SOURCE-PATH')
            base = Path(path).name
            if base and base != path:
                data = data.replace(base.encode('utf-8'), b'REDACTED-SOURCE-PATH')
        return data

    def scrub_string(self, s):
        out = s
        for token in self.tokens:
            if token in out:
                out = out.replace(token, self.pseudonym(token))
        for path in self.paths:
            if path in out:
                out = out.replace(path, 'REDACTED-SOURCE-PATH')
            base = Path(path).name
            if base and base != path and base in out:
                out = out.replace(base, 'REDACTED-SOURCE-PATH')
        # A Base64 string may carry the raw private bytes (report copies,
        # attachments, ...): always re-scan its decoded content so a BLOB
        # cannot hide identity behind an encoding.
        if self._looks_like_b64(s):
            decoded = base64.b64decode(s)
            if any(t.encode() in decoded for t in self.tokens) or \
               any(p.encode() in decoded for p in self.paths) or \
               any(Path(p).name.encode() in decoded for p in self.paths if Path(p).name):
                return self._scrub_b64(s)
        return out

    def scrub(self, obj):
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                if self._is_drop_key(k):
                    continue
                if self._is_identity_key(k) and isinstance(v, str) and v:
                    # Identity scalars always become recipient pseudonyms,
                    # even when the literal value was not a listed token.
                    result[k] = self.pseudonym(v)
                else:
                    result[k] = self.scrub(v)
            return result
        if isinstance(obj, list):
            return [self.scrub(v) for v in obj]
        if isinstance(obj, str):
            return self.scrub_string(obj)
        return obj

    def scrub_text(self, text):
        return self.scrub_string(text)


def rebuild_source_bytes(raw, name, scrubber):
    """Rebuild a restricted source file byte stream from the original bytes.

    A recipient-bound provenance marker is prepended so that the rebuilt
    stream (and its export SHA) change when the pseudonym key rotates, while
    remaining independent of the original source hash.
    """
    marker = json.dumps({'_restricted_export': True,
                         '_binding': scrubber.source_binding},
                        ensure_ascii=False)
    text = raw.decode('utf-8-sig')
    if str(name).lower().endswith('.csv'):
        reader = csv.reader(io.StringIO(text))
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator='\n')
        for row in reader:
            writer.writerow([scrubber.scrub_string(cell) for cell in row])
        return (marker + '\n' + buf.getvalue()).encode('utf-8')
    kept = [marker]
    for line in text.splitlines():
        if not line.strip():
            kept.append(line)
            continue
        try:
            # Canonical form so each rebuilt event line equals the exported
            # event payload serialization byte-for-byte.
            kept.append(_canonical(scrubber.scrub(json.loads(line))))
        except json.JSONDecodeError:
            kept.append(scrubber.scrub_text(line))
    out = '\n'.join(kept)
    if text.endswith('\n'):
        out += '\n'
    return out.encode('utf-8')


# ---------------------------------------------------------------------------
# Recipient-bound ids and commitments
# ---------------------------------------------------------------------------

def _recipient_secret(salt, recipient_id):
    return hmac.new(bytes(salt), ('recipient:' + recipient_id).encode(),
                    hashlib.sha256).digest()


def _hmac_id(secret, message, length=16):
    return hmac.new(secret, message.encode(), hashlib.sha256).hexdigest()[:length]


def _regulator_id(kind, original):
    return {'source': 'SRC-%s' % original,
            'event': 'EVT-%s' % original,
            'issue': 'ISS-%s' % original,
            'evidence': 'EVD-%s' % original,
            'run': 'RUN-%s' % original,
            'decision': 'DEC-%s' % original}[kind]


# ---------------------------------------------------------------------------
# Snapshot + package building
# ---------------------------------------------------------------------------

def _snapshot(db):
    return {
        'sources': [dict(r) for r in db.execute('SELECT * FROM source_file ORDER BY id')],
        'events': [dict(r) for r in db.execute('SELECT * FROM raw_event ORDER BY id')],
        'issues': [dict(r) for r in db.execute('SELECT * FROM issue ORDER BY id')],
        'evidence': [dict(r) for r in db.execute('SELECT * FROM evidence ORDER BY id')],
        'decisions': [dict(r) for r in db.execute('SELECT * FROM decision ORDER BY box_id')],
        'runs': [dict(r) for r in db.execute('SELECT * FROM run ORDER BY id')],
    }


def _build_regulator(snap):
    """Byte-faithful view: every original id, hash and BLOB is retained."""
    sources, events = [], []
    used_names = set()
    for s in snap['sources']:
        stem = Path(s['name']).stem or 'source'
        ext = Path(s['name']).suffix or '.bin'
        rel = 'sources/%s%s' % (stem, ext)
        # Disambiguate same-named sources from different directories.
        if rel in used_names:
            rel = 'sources/%s-%d%s' % (stem, s['id'], ext)
        used_names.add(rel)
        sources.append({
            'export_id': _regulator_id('source', s['id']),
            'original_id': s['id'], 'name': s['name'], 'hash': s['hash'],
            'raw_base64': base64.b64encode(bytes(s['raw'])).decode('ascii'),
            'file': rel,
        })
    src_index = {s['original_id']: s for s in sources}
    for e in snap['events']:
        events.append({
            'export_id': _regulator_id('event', e['id']),
            'original_id': e['id'], 'original_hash': e['hash'],
            'source_export_id': src_index[e['source_id']]['export_id'],
            'line_no': e['line_no'], 'kind': e['kind'], 'device': e['device'],
            'seq': e['seq'], 'box_id': e['box_id'], 'event_time': e['event_time'],
            'payload': json.loads(e['payload']), 'hash': e['hash'],
        })
    ev_index = {e['original_id']: e['export_id'] for e in events}
    issues = [{
        'export_id': _regulator_id('issue', i['id']), 'original_id': i['id'],
        'event_export_id': ev_index.get(i['event_id']),
        'code': i['code'], 'detail': i['detail'],
    } for i in snap['issues']]
    runs = [{
        'export_id': _regulator_id('run', r['id']), 'original_id': r['id'],
        'rules_version': r['rules_version'], 'source_digest': r['source_digest'],
    } for r in snap['runs']]
    run_index = {r['original_id']: r['export_id'] for r in runs}
    evidence = [{
        'export_id': _regulator_id('evidence', x['id']), 'original_id': x['id'],
        'run_export_id': run_index[x['run_id']], 'subject_id': x['subject_id'],
        'source_export_id': src_index[x['source_id']]['export_id'],
        'object_kind': x['object_kind'],
        'object_export_id': ev_index.get(x['object_id'], str(x['object_id'])),
        'detail': x['detail'],
    } for x in snap['evidence']]
    decisions = []
    for d in snap['decisions']:
        detail = json.loads(d['detail'])
        detail['events'] = [ev_index.get(eid, str(eid)) for eid in detail.get('events', [])]
        decisions.append({
            'export_id': _regulator_id('decision', d['box_id']),
            'box_id': d['box_id'], 'result': d['result'],
            'detail': json.dumps(detail, ensure_ascii=False),
            'rules_version': d['rules_version'],
            'run_export_id': run_index[d['run_id']],
        })
    source_digest = _sha256('|'.join(s['hash'] for s in sources))
    raw_by_id = {s['id']: bytes(s['raw']) for s in snap['sources']}
    return {
        'sources': sources, 'events': events, 'issues': issues,
        'evidence': evidence, 'decisions': decisions, 'runs': runs,
        'commitment': source_digest, 'source_digest': source_digest,
        'source_files': [(s['file'], raw_by_id[s['original_id']]) for s in sources],
        'maps': _regulator_maps(snap, sources, events, issues, evidence, runs, decisions),
    }


def _regulator_maps(snap, sources, events, issues, evidence, runs, decisions):
    maps = []
    for s, view in zip(snap['sources'], sources):
        maps.append(('source', str(s['id']), s['hash'], view['export_id'], s['hash']))
    for e, view in zip(snap['events'], events):
        maps.append(('event', str(e['id']), e['hash'], view['export_id'], e['hash']))
    for i, view in zip(snap['issues'], issues):
        maps.append(('issue', str(i['id']), None, view['export_id'], None))
    for x, view in zip(snap['evidence'], evidence):
        maps.append(('evidence', str(x['id']), None, view['export_id'], None))
    for r, view in zip(snap['runs'], runs):
        maps.append(('run', r['id'], None, view['export_id'], None))
    for d, view in zip(snap['decisions'], decisions):
        maps.append(('decision', d['box_id'], None, view['export_id'], None))
    return maps


def _build_partner(snap, contract, salt, recipient_id):
    """Rebuilt view: private identity, paths and BLOBs cannot survive."""
    secret = _recipient_secret(salt, recipient_id)
    drop_fields = contract.get('partner_drop_fields', [])
    tokens = contract.get('sensitive_tokens', [])
    paths = [s['name'] for s in snap['sources']]
    scrubber = Scrubber(secret, tokens, paths, drop_fields)

    # 1. Rebuild source bytes and recompute export source hashes.
    sources, rebuilt_raw = [], {}
    for s in snap['sources']:
        rebuilt = rebuild_source_bytes(bytes(s['raw']), s['name'], scrubber)
        export_hash = _sha256(rebuilt)
        export_id = _hmac_id(secret, 'source:' + str(s['id']))
        ext = Path(s['name']).suffix or '.bin'
        file_rel = 'sources/source-%s%s' % (export_id[:12], ext)
        sources.append({
            'export_id': export_id, 'export_hash': export_hash,
            'file': file_rel, 'rebuilt_from': 'rebuilt-restricted-view',
        })
        rebuilt_raw[s['id']] = (file_rel, rebuilt)
    src_index = {s['id']: view for s, view in zip(snap['sources'], sources)}

    # 2. Scrub every event payload; recompute event hashes.
    events = []
    for e in snap['events']:
        payload = scrubber.scrub(json.loads(e['payload']))
        export_hash = _sha256(_canonical(payload))
        events.append({
            'export_id': _hmac_id(secret, 'event:' + str(e['id'])),
            'source_export_id': src_index[e['source_id']]['export_id'],
            'line_no': e['line_no'], 'kind': e['kind'], 'device': e['device'],
            'seq': e['seq'], 'box_id': e['box_id'], 'event_time': e['event_time'],
            'payload': payload, 'export_hash': export_hash,
        })
    ev_index = {e['id']: view['export_id'] for e, view in zip(snap['events'], events)}

    # 3. Runs carry a recipient-bound commitment, never the real digest.
    real_digest = _sha256('|'.join(s['hash'] for s in snap['sources']))
    commitment = _hmac_id(secret, 'source-digest:' + real_digest, length=32)
    runs = [{
        'export_id': _hmac_id(secret, 'run:' + r['id']),
        'rules_version': r['rules_version'], 'source_digest_commitment': commitment,
    } for r in snap['runs']]
    run_index = {r['id']: view['export_id'] for r, view in zip(snap['runs'], runs)}

    # 4. Issue codes survive; free-text details are scrubbed.
    issues = [{
        'export_id': _hmac_id(secret, 'issue:' + str(i['id'])),
        'event_export_id': ev_index.get(i['event_id']),
        'code': i['code'], 'detail': scrubber.scrub_text(i['detail']),
    } for i in snap['issues']]

    # 5. Evidence chain is rewritten onto export ids.  Only evidence whose
    # referenced object still exists is exported, keeping the graph closed.
    evidence = [{
        'export_id': _hmac_id(secret, 'evidence:' + x['id']),
        'run_export_id': run_index[x['run_id']], 'subject_id': x['subject_id'],
        'source_export_id': src_index[x['source_id']]['export_id'],
        'object_kind': x['object_kind'],
        'object_export_id': ev_index[x['object_id']],
        'detail': scrubber.scrub_text(x['detail']),
    } for x in snap['evidence'] if x['object_id'] in ev_index]

    # 6. Decisions keep box traceability; the embedded event list is remapped.
    decisions = []
    for d in snap['decisions']:
        detail = json.loads(d['detail'])
        detail = scrubber.scrub(detail)
        detail['events'] = [ev_index.get(eid, str(eid)) for eid in detail.get('events', [])]
        decisions.append({
            'export_id': _hmac_id(secret, 'decision:' + d['box_id']),
            'box_id': d['box_id'], 'result': d['result'],
            'detail': json.dumps(detail, ensure_ascii=False),
            'rules_version': d['rules_version'],
            'run_export_id': run_index[d['run_id']],
        })

    maps = [('identity', token, None, pseud, None)
            for token, pseud in sorted(scrubber.pseudonyms.items())]
    for s, view in zip(snap['sources'], sources):
        maps.append(('source', str(s['id']), s['hash'], view['export_id'], view['export_hash']))
    for e, view in zip(snap['events'], events):
        maps.append(('event', str(e['id']), e['hash'], view['export_id'], view['export_hash']))
    for i, view in zip(snap['issues'], issues):
        maps.append(('issue', str(i['id']), None, view['export_id'], None))
    for x, view in zip(snap['evidence'], evidence):
        maps.append(('evidence', str(x['id']), None, view['export_id'], None))
    for r, view in zip(snap['runs'], runs):
        maps.append(('run', r['id'], None, view['export_id'], None))
    for d, view in zip(snap['decisions'], decisions):
        maps.append(('decision', d['box_id'], None, view['export_id'], None))

    return {
        'sources': sources, 'events': events, 'issues': issues,
        'evidence': evidence, 'decisions': decisions, 'runs': runs,
        'commitment': commitment, 'source_digest': None,
        'source_files': list(rebuilt_raw.values()),
        'maps': maps, 'pseudonyms': dict(scrubber.pseudonyms),
    }


def _write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True),
                    encoding='utf-8')


def _render_markdown(kind, view, contract):
    lines = ['# 冷链交接证据包（%s）' % kind, '']
    lines.append('## 箱号判定')
    if view['decisions']:
        for d in view['decisions']:
            lines.append('- 箱 %s: %s（规则 %s）' % (d['box_id'], d['result'], d['rules_version']))
    else:
        lines.append('- （本包无判定记录）')
    lines.append('')
    lines.append('## 问题代码')
    if view['issues']:
        for i in view['issues']:
            lines.append('- %s%s' % (i['code'],
                                    ('：' + i['detail']) if kind == REGULATOR and i['detail'] else ''))
    else:
        lines.append('- （无 issue）')
    lines.append('')
    lines.append('## 来源与事件')
    lines.append('- 来源文件数：%d；事件数：%d；证据链数：%d'
                 % (len(view['sources']), len(view['events']), len(view['evidence'])))
    if kind == REGULATOR:
        for s in view['sources']:
            lines.append('- 原始来源 %s SHA256=%s' % (s['name'], s['hash']))
    else:
        for s in view['sources']:
            lines.append('- 重建受限来源 %s 导出SHA256=%s' % (s['export_id'], s['export_hash']))
    lines.append('')
    lines.append('收件合同：%s；保留字段：%s'
                 % (kind, ', '.join(contract.get('partner_keep_fields', [])) or '全部'))
    return '\n'.join(lines) + '\n'


def _package_dirs(out_root, case_id, kind, recipient_id, version):
    base = Path(out_root) / case_id / ('%s-%s' % (kind, recipient_id)) / ('v%d' % version)
    return base, Path(str(base) + '.staging-tmp')


def _write_package(staging, kind, view, contract, manifest_extra):
    payload_files = {
        'sources.json': view['sources'], 'events.json': view['events'],
        'issues.json': view['issues'], 'evidence.json': view['evidence'],
        'decisions.json': view['decisions'], 'runs.json': view['runs'],
    }
    for rel, obj in payload_files.items():
        _write_json(staging / rel, obj)
    for rel, data in view['source_files']:
        p = staging / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    (staging / 'report.md').write_text(
        _render_markdown(kind, view, contract), encoding='utf-8')

    files = {}
    for p in sorted(staging.rglob('*')):
        if p.is_file():
            files[str(p.relative_to(staging))] = _sha256(p.read_bytes())
    content_digest = _sha256(_canonical(payload_files))
    manifest = {
        'format_version': 1,
        'contract_kind': kind,
        'recipient_id': manifest_extra['recipient_id'],
        'case_id': manifest_extra['case_id'],
        'package_id': manifest_extra['package_id'],
        'version': manifest_extra['version'],
        'key_id': manifest_extra['key_id'],
        'created_at': manifest_extra['created_at'],
        'contract_sha256': manifest_extra['contract_sha256'],
        'frozen_source_digest': view['source_digest'],
        'source_digest_commitment': view['commitment'],
        'counts': {k: len(v) for k, v in payload_files.items()},
        'content_digest': content_digest,
        'files': files,
    }
    # The manifest cannot hash itself; its own integrity is covered by
    # content_digest plus the hashes of every payload file it lists.
    _write_json(staging / 'manifest.json', manifest)
    return manifest


# ---------------------------------------------------------------------------
# Leak scanning (used before any partner package is confirmed)
# ---------------------------------------------------------------------------

def scan_bytes(data, forbidden):
    hits = []
    for needle in forbidden:
        if needle and needle.encode('utf-8') in data:
            hits.append(needle)
    return hits


def _recursive_scan(obj, forbidden):
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            hits.extend(_recursive_scan(k, forbidden))
            hits.extend(_recursive_scan(v, forbidden))
    elif isinstance(obj, list):
        for v in obj:
            hits.extend(_recursive_scan(v, forbidden))
    elif isinstance(obj, str):
        for needle in forbidden:
            if needle and needle in obj:
                hits.append(needle)
        if Scrubber._looks_like_b64(obj):
            try:
                hits.extend(scan_bytes(base64.b64decode(obj), forbidden))
            except (binascii.Error, ValueError):
                pass
    return hits


def scan_package(root, forbidden_tokens, forbidden_paths):
    """Recursively scan JSON text, Markdown and Base64-decoded bytes."""
    forbidden = list(forbidden_tokens) + list(forbidden_paths)
    forbidden += [Path(p).name for p in forbidden_paths if Path(p).name]
    forbidden = sorted(set(forbidden))
    findings = []
    root = Path(root)
    for p in sorted(root.rglob('*')):
        if not p.is_file():
            continue
        rel = str(p.relative_to(root))
        raw = p.read_bytes()
        for needle in scan_bytes(raw, forbidden):
            findings.append({'file': rel, 'needle': needle, 'where': 'raw_bytes'})
        if p.suffix == '.json':
            try:
                for needle in set(_recursive_scan(json.loads(raw.decode('utf-8')), forbidden)):
                    findings.append({'file': rel, 'needle': needle, 'where': 'json_recursive'})
            except json.JSONDecodeError:
                pass
    return findings


# ---------------------------------------------------------------------------
# Staging / confirmation / resume
# ---------------------------------------------------------------------------

def _build_view(db, snap, contract_kind, contract, key_id, recipient_id):
    if contract_kind == REGULATOR:
        return _build_regulator(snap), ''
    key_row = db.execute('SELECT * FROM pseudonym_key WHERE key_id=?',
                         (key_id,)).fetchone()
    if not key_row:
        raise ExportError('unknown_key:%s' % key_id)
    return _build_partner(snap, contract, key_row['salt'], recipient_id), key_id


def stage_export(db_path, case_id, contract_kind, out_root,
                 recipient_id=None, key_id=None):
    """Build a new immutable package version (or return the identical one)."""
    if contract_kind not in KNOWN_CONTRACTS:
        raise ExportError('unknown_contract_kind:%s' % contract_kind)
    recipient_id = recipient_id or DEFAULT_RECIPIENT[contract_kind]
    db = connect(db_path)
    db.execute('BEGIN IMMEDIATE')
    closed = False
    try:
        case = db.execute('SELECT * FROM export_case WHERE id=?', (case_id,)).fetchone()
        if not case:
            raise ExportError('unknown_case')
        contract = json.loads(case['contract_json'])
        if contract_kind not in contract.get('recipient_contracts', []):
            raise ExportError('contract_not_authorized')
        live_digest = _source_digest(db)
        if live_digest != case['source_digest']:
            raise FrozenDigestMismatch(
                'frozen=%s live=%s' % (case['source_digest'], live_digest))

        existing = db.execute(
            'SELECT * FROM export_package WHERE case_id=? AND contract_kind=? '
            'AND recipient_id=? ORDER BY version DESC',
            (case_id, contract_kind, recipient_id)).fetchall()
        if contract_kind == PARTNER:
            if key_id is None:
                key_id = _latest_key_id(db)
        else:
            key_id = ''
        for row in existing:
            if row['status'] != FAILED and row['key_id'] == key_id \
                    and row['frozen_source_digest'] == case['source_digest'] \
                    and row['contract_sha256'] == case['contract_sha256']:
                db.rollback(); db.close(); closed = True
                return _package_handle(db_path, row['id'], out_root, reused=True)

        version = (existing[0]['version'] + 1) if existing else 1
        package_id = 'pkg-%s-%s-v%d' % (case_id, recipient_id, version)
        snap = _snapshot(db)
        view, key_id = _build_view(db, snap, contract_kind, contract, key_id, recipient_id)

        final_dir, staging = _package_dirs(out_root, case_id, contract_kind,
                                           recipient_id, version)
        if staging.exists():
            # Leftover of an interrupted attempt with this version id: remove.
            import shutil
            shutil.rmtree(staging)
        staging.mkdir(parents=True)
        manifest = _write_package(staging, contract_kind, view, contract, {
            'case_id': case_id, 'package_id': package_id, 'version': version,
            'recipient_id': recipient_id, 'key_id': key_id,
            'created_at': _now(), 'contract_sha256': case['contract_sha256'],
        })
        db.execute(
            'INSERT INTO export_package(id,case_id,contract_kind,recipient_id,version,'
            'key_id,frozen_source_digest,digest_commitment,contract_sha256,status,'
            'content_digest,manifest_json,staged_at,confirmed_at,receipt_json) '
            'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (package_id, case_id, contract_kind, recipient_id, version, key_id,
             case['source_digest'], view['commitment'], case['contract_sha256'],
             STAGED, manifest['content_digest'], json.dumps(manifest, ensure_ascii=False),
             _now(), None, None))
        for kind, oid, ohash, eid, ehash in view['maps']:
            db.execute('INSERT INTO export_id_map(package_id,object_kind,original_id,'
                       'original_hash,export_id,export_hash) VALUES (?,?,?,?,?,?)',
                       (package_id, kind, str(oid), ohash, eid, ehash))
        db.commit()
        handle = _package_handle(db_path, package_id, out_root)
        db.close(); closed = True
        return handle
    finally:
        if not closed:
            db.rollback(); db.close()


def rebuild_staging(db_path, row, out_root):
    """Deterministically recreate a lost staging directory for an existing row."""
    db = connect(db_path)
    db.execute('BEGIN IMMEDIATE')
    closed = False
    try:
        case = db.execute('SELECT * FROM export_case WHERE id=?', (row['case_id'],)).fetchone()
        contract = json.loads(case['contract_json'])
        if _source_digest(db) != case['source_digest']:
            raise FrozenDigestMismatch('cannot_rebuild_drifted_sources')
        snap = _snapshot(db)
        view, _ = _build_view(db, snap, row['contract_kind'], contract,
                              row['key_id'], row['recipient_id'])
        final_dir, staging = _package_dirs(out_root, row['case_id'], row['contract_kind'],
                                           row['recipient_id'], row['version'])
        import shutil
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True)
        manifest = _write_package(staging, row['contract_kind'], view, contract, {
            'case_id': row['case_id'], 'package_id': row['id'],
            'version': row['version'], 'recipient_id': row['recipient_id'],
            'key_id': row['key_id'], 'created_at': row['staged_at'],
            'contract_sha256': row['contract_sha256'],
        })
        if manifest['content_digest'] != row['content_digest']:
            raise ExportError('rebuilt_content_differs_from_frozen_package')
        db.commit(); db.close(); closed = True
        return staging
    finally:
        if not closed:
            db.rollback(); db.close()


def _package_handle(db_path, package_id, out_root, reused=False):
    db = connect(db_path)
    row = db.execute('SELECT * FROM export_package WHERE id=?', (package_id,)).fetchone()
    final_dir, staging = _package_dirs(out_root, row['case_id'], row['contract_kind'],
                                       row['recipient_id'], row['version'])
    handle = {
        'package_id': package_id, 'case_id': row['case_id'],
        'contract_kind': row['contract_kind'], 'recipient_id': row['recipient_id'],
        'version': row['version'], 'status': row['status'],
        'key_id': row['key_id'], 'content_digest': row['content_digest'],
        'staging_dir': str(staging), 'package_dir': str(final_dir),
        'reused': reused,
    }
    db.close()
    return handle


def confirm_export(db_path, package_id, out_root):
    """Scan, atomically publish and write the recipient receipt."""
    db = connect(db_path)
    db.execute('BEGIN IMMEDIATE')
    closed = False
    try:
        row = db.execute('SELECT * FROM export_package WHERE id=?', (package_id,)).fetchone()
        if not row:
            raise ExportError('unknown_package')
        if row['status'] == CONFIRMED:
            db.rollback(); db.close(); closed = True
            return _package_handle(db_path, package_id, out_root, reused=True)
        final_dir, staging = _package_dirs(out_root, row['case_id'], row['contract_kind'],
                                           row['recipient_id'], row['version'])
        if not staging.exists():
            raise ExportError('staging_missing_resume_first')
        verification = verify_package(staging, db_path=db_path, _db=db)
        if row['contract_kind'] == PARTNER and verification['leak_findings']:
            db.execute("UPDATE export_package SET status=? WHERE id=?", (FAILED, package_id))
            db.commit(); db.close(); closed = True
            raise LeakDetected(json.dumps(verification['leak_findings'], ensure_ascii=False))
        if final_dir.exists():
            raise ExportError('immutable_package_dir_exists')
        staging.rename(final_dir)
        receipt = {
            'package_id': package_id, 'case_id': row['case_id'],
            'contract_kind': row['contract_kind'], 'recipient_id': row['recipient_id'],
            'version': row['version'], 'key_id': row['key_id'],
            'content_digest': row['content_digest'],
            'digest_commitment': row['digest_commitment'],
            'confirmed_at': _now(), 'verification': verification['checks'],
        }
        (final_dir / 'receipt.json').write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True),
            encoding='utf-8')
        (final_dir / 'verify').mkdir(exist_ok=True)
        (final_dir / 'verify' / 'verification.json').write_text(
            json.dumps(verification, ensure_ascii=False, indent=2, sort_keys=True),
            encoding='utf-8')
        db.execute('UPDATE export_package SET status=?,confirmed_at=?,receipt_json=? WHERE id=?',
                   (CONFIRMED, receipt['confirmed_at'],
                    json.dumps(receipt, ensure_ascii=False), package_id))
        db.commit(); db.close(); closed = True
        return _package_handle(db_path, package_id, out_root)
    finally:
        if not closed:
            db.rollback(); db.close()


def resume_export(db_path, case_id, contract_kind, recipient_id, out_root):
    """Rebuild interrupted staging, then finish confirmation if possible."""
    db = connect(db_path)
    row = db.execute(
        'SELECT * FROM export_package WHERE case_id=? AND contract_kind=? AND recipient_id=? '
        'ORDER BY version DESC LIMIT 1',
        (case_id, contract_kind, recipient_id)).fetchone()
    db.close()
    if not row:
        raise ExportError('unknown_package')
    final_dir, staging = _package_dirs(out_root, case_id, contract_kind,
                                       recipient_id, row['version'])
    if row['status'] == CONFIRMED and final_dir.exists():
        return _package_handle(db_path, row['id'], out_root, reused=True)
    if not staging.exists():
        # The row exists but its bytes were lost: rebuild the exact frozen
        # content deterministically (refusing to mix in drifted sources).
        rebuild_staging(db_path, row, out_root)
    return confirm_export(db_path, row['id'], out_root)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _load(root):
    root = Path(root)
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    data = {name: json.loads((root / ('%s.json' % name)).read_text(encoding='utf-8'))
            for name in ('sources', 'events', 'issues', 'evidence', 'decisions', 'runs')}
    return manifest, data


def verify_package(path, db_path=None, forbidden_tokens=None,
                   forbidden_paths=None, _db=None):
    """Independently verify a package.

    Without a database: manifest hashes, the source->event->evidence->
    decision reference graph and rebuilt-source consistency are checked.
    With a database: regulator byte fidelity against the stored BLOBs and
    recursive partner leak scanning are additionally enforced.
    """
    root = Path(path)
    manifest, data = _load(root)
    kind = manifest['contract_kind']
    checks = []

    def check(name, ok, detail=''):
        checks.append({'name': name, 'ok': bool(ok), 'detail': detail})

    # 1. Every recorded file hash must match the bytes on disk.
    # manifest.json is self-describing and intentionally not self-hashed.
    file_ok = True
    for rel, want in manifest['files'].items():
        p = root / rel
        ok = p.exists() and _sha256(p.read_bytes()) == want
        file_ok &= ok
        check('file_hash:' + rel, ok)
    check('all_file_hashes', file_ok)
    check('manifest_present', (root / 'manifest.json').exists())

    source_ids = {s['export_id'] for s in data['sources']}
    event_ids = {e['export_id'] for e in data['events']}
    run_ids = {r['export_id'] for r in data['runs']}

    # 2. Reference graph closure: no dangling objects.
    dangling = []
    for e in data['events']:
        if e['source_export_id'] not in source_ids:
            dangling.append(('event', e['export_id'], 'source', e['source_export_id']))
    for i in data['issues']:
        if i['event_export_id'] is not None and i['event_export_id'] not in event_ids:
            dangling.append(('issue', i['export_id'], 'event', i['event_export_id']))
    for x in data['evidence']:
        if x['run_export_id'] not in run_ids:
            dangling.append(('evidence', x['export_id'], 'run', x['run_export_id']))
        if x['source_export_id'] not in source_ids:
            dangling.append(('evidence', x['export_id'], 'source', x['source_export_id']))
        if x['object_kind'] == 'raw_event' and x['object_export_id'] not in event_ids:
            dangling.append(('evidence', x['export_id'], 'event', x['object_export_id']))
    for d in data['decisions']:
        if d['run_export_id'] not in run_ids:
            dangling.append(('decision', d['box_id'], 'run', d['run_export_id']))
        for eid in json.loads(d['detail']).get('events', []):
            if eid not in event_ids:
                dangling.append(('decision', d['box_id'], 'event', eid))
    check('reference_graph_closed', not dangling, json.dumps(dangling))

    # 3. Source files and their recorded hashes.
    source_hash_ok = True
    for s in data['sources']:
        p = root / s['file']
        if kind == REGULATOR:
            expect = base64.b64decode(s['raw_base64'])
            ok = p.exists() and p.read_bytes() == expect and _sha256(expect) == s['hash']
        else:
            ok = p.exists() and _sha256(p.read_bytes()) == s['export_hash']
        source_hash_ok &= ok
        check('source_bytes:' + s['export_id'][:16], ok)
    check('source_hashes', source_hash_ok)

    # 4. Partner: rebuilt sources must actually contain the exported events.
    if kind == PARTNER:
        embedded_ok = True
        for s in data['sources']:
            text = (root / s['file']).read_text(encoding='utf-8')
            is_csv = s['file'].lower().endswith('.csv')
            for e in (x for x in data['events']
                      if x['source_export_id'] == s['export_id']):
                if is_csv:
                    # every scalar payload value survives in a CSV cell
                    cells = {cell for row in csv.reader(io.StringIO(text))
                             for cell in row}
                    ok = all(str(v) in cells for v in e['payload'].values()
                             if not isinstance(v, (dict, list)))
                else:
                    ok = _canonical(e['payload']) in text.splitlines()
                embedded_ok &= ok
        check('events_embedded_in_rebuilt_sources', embedded_ok)
        check('export_hashes_not_original', all('export_hash' in s for s in data['sources']))

    leak_findings = []
    db = _db
    close = False
    if db is None and db_path is not None:
        db = connect(db_path)
        close = True
    if db is not None:
        pkg = db.execute('SELECT * FROM export_package WHERE id=?',
                         (manifest['package_id'],)).fetchone()
        case = db.execute('SELECT * FROM export_case WHERE id=?',
                          (manifest['case_id'],)).fetchone()
        if pkg and case:
            contract = json.loads(case['contract_json'])
            if kind == PARTNER:
                forbidden_tokens = forbidden_tokens if forbidden_tokens is not None \
                    else contract.get('sensitive_tokens', [])
                forbidden_paths = forbidden_paths if forbidden_paths is not None \
                    else [r['name'] for r in db.execute('SELECT name FROM source_file')]
                leak_findings = scan_package(root, forbidden_tokens, forbidden_paths)
                check('no_private_leak', not leak_findings,
                      json.dumps(leak_findings, ensure_ascii=False))
                # Original source SHAs must never appear in the partner package.
                original_hashes = [r['hash'] for r in db.execute('SELECT hash FROM source_file')]
                blob = b''.join(p.read_bytes() for p in root.rglob('*') if p.is_file())
                check('no_original_source_hash',
                      all(h.encode() not in blob for h in original_hashes))
                # The private mapping must not be inside the package.
                check('no_mapping_table', not (root / 'id_map.json').exists())
            else:
                # Regulator: byte-faithful against the database BLOBs.
                rows = {r['id']: r for r in db.execute('SELECT * FROM source_file')}
                faithful = True
                for s in data['sources']:
                    raw = bytes(rows[s['original_id']]['raw'])
                    faithful &= (root / s['file']).read_bytes() == raw
                    faithful &= s['hash'] == rows[s['original_id']]['hash']
                check('regulator_byte_fidelity', faithful)
                check('regulator_original_digest',
                      manifest['frozen_source_digest'] == case['source_digest'])
    if close:
        db.close()

    ok = all(c['ok'] for c in checks)
    return {'package_id': manifest['package_id'], 'contract_kind': kind,
            'recipient_id': manifest['recipient_id'], 'version': manifest['version'],
            'ok': ok, 'checks': checks, 'leak_findings': leak_findings}
