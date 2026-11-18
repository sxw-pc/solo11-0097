"""Deterministic physical label sheet rendering (frozen template TPL-1).

A sheet is the exact byte string sent to the printer and later read back by
the verifier. Its payload is canonical JSON; the printed SHA256 line is the
digest of those payload bytes. Two authorised layouts exist:

* ``direct_recipient`` prints the customer name on paper;
* ``opaque_pickup`` prints only a pickup token — the recipient stays in the
  private contract mapping and is never present in the sheet bytes.
"""
import json
from hashlib import sha256

TEMPLATE_VERSION = 'TPL-1'
DIRECT = 'direct_recipient'
OPAQUE = 'opaque_pickup'
MODES = (DIRECT, OPAQUE)


def _canonical(doc):
    return json.dumps(doc, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':')).encode('utf-8')


def binding_digest(*, case_id, contract_sha256, box_id, recipient, opaque_id):
    """Digest binding the source box and its recipient contract snapshot.

    Any change to the box/recipient contract changes this value, so bytes
    rendered for an older contract can never match a new binding.
    """
    doc = {'case_id': case_id, 'contract_sha256': contract_sha256,
           'box_id': box_id, 'recipient': recipient, 'opaque_id': opaque_id}
    return sha256(_canonical(doc)).hexdigest()


def render_sheet(*, case_id, contract_sha256, box_id, serial, mode,
                 recipient, opaque_id):
    if mode not in MODES:
        raise ValueError('unknown_mode')
    source = binding_digest(case_id=case_id, contract_sha256=contract_sha256,
                            box_id=box_id, recipient=recipient,
                            opaque_id=opaque_id)
    if mode == DIRECT:
        party_field, party = 'RECIPIENT', recipient
    else:
        party_field, party = 'PICKUP', opaque_id
    payload = {'template': TEMPLATE_VERSION, 'case_id': case_id,
               'box_id': box_id, 'serial': serial, 'mode': mode,
               party_field.lower(): party, 'source_digest': source}
    payload_bytes = _canonical(payload)
    content_sha256 = sha256(payload_bytes).hexdigest()
    lines = ['COLDSHIP-LABEL ' + TEMPLATE_VERSION,
             'BOX:' + box_id,
             'SERIAL:' + serial,
             'MODE:' + mode,
             party_field + ':' + party,
             'SOURCE-DIGEST:' + source,
             'PAYLOAD:' + payload_bytes.decode('utf-8'),
             'SHA256:' + content_sha256]
    sheet_bytes = ('\n'.join(lines) + '\n').encode('utf-8')
    return {'payload_bytes': payload_bytes, 'sheet_bytes': sheet_bytes,
            'content_sha256': content_sha256, 'source_digest': source,
            'mode': mode, 'serial': serial, 'box_id': box_id,
            'template_version': TEMPLATE_VERSION}


def parse_sheet(sheet_bytes):
    """Parse a physical sheet, recomputing its embedded digest.

    Returns the payload document and digest. ``digest_valid`` is False when
    the paper was altered; the caller must never trust such a reading.
    """
    text = bytes(sheet_bytes).decode('utf-8')
    fields = {}
    payload_line = None
    digest_line = None
    for line in text.splitlines():
        if line.startswith('PAYLOAD:'):
            payload_line = line[len('PAYLOAD:'):]
        elif line.startswith('SHA256:'):
            digest_line = line[len('SHA256:'):]
        elif ':' in line:
            key, value = line.split(':', 1)
            fields[key] = value
    if payload_line is None or digest_line is None:
        raise ValueError('malformed_sheet')
    recomputed = sha256(payload_line.encode('utf-8')).hexdigest()
    doc = json.loads(payload_line)
    return {'payload': doc, 'printed_sha256': digest_line,
            'content_sha256': recomputed,
            'digest_valid': recomputed == digest_line,
            'serial': doc['serial'], 'box_id': doc['box_id'],
            'mode': doc['mode']}
