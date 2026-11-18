"""Offline carrier tariff capture, service-identity merge, versioned rate master and customer quotes.

Pipeline (every step cites the frozen source bytes/SHA stored by ``register``):

    frozen pages (HTML/CSV/signed addendum)
      -> page-chain & revision verification, field extraction
      -> identity merge (carrier + service identity + storage temperature + validity + weight band)
      -> interval rate graph with quarantine for overlaps/gaps/conflicts
      -> candidate master-data version (whole-graph validated, version fence)
      -> mock downstream rate-master publication with ACK
      -> customer quotes that only read ACKed published version IDs

This module never decides vehicle loading, never reads temperature decisions and never
settles bank money. Room-temperature services are always listed separately from cold-chain
services and are never merged on a similar service name.
"""
import csv
import hashlib
import io
import json
import re
import sqlite3
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

from .ingest import parse_time
from .store import connect

MAX_CARRIERS = 4
MAX_PAGES = 30
MAX_BANDS = 100
DIMENSIONAL_DIVISOR = 5000
ALLOWED_AUTHORITIES = ('public_tariff', 'signed_addendum')
VALID_TEMP = re.compile(r'^\d+(?:\.\d+)?-\d+(?:\.\d+)?C$')


class TariffError(ValueError):
    """Blocking tariff integrity failure; the old current version stays queryable."""


# --------------------------------------------------------------------------- #
# frozen case registration (real box arrival + raw source bytes/SHA)
# --------------------------------------------------------------------------- #

def register(db_path, case_id, contract_path, source_dir):
    """Freeze the real box-A arrival, its source SHA and the raw tariff source bytes."""
    contract_path = Path(contract_path).resolve()
    source_dir = Path(source_dir).resolve()
    raw = contract_path.read_bytes()
    contract = json.loads(raw)
    if not case_id or not contract.get('source_pages') or not contract.get('publish_target'):
        raise ValueError('tariff_contract_invalid')
    sources = []
    for name in contract['source_pages']:
        path = (source_dir / name).resolve()
        if path.parent != source_dir or path.suffix not in {'.html', '.csv', '.json'}:
            raise ValueError('tariff_source_invalid')
        body = path.read_bytes()
        sources.append({'name': name, 'sha256': hashlib.sha256(body).hexdigest(),
                        'body': body.decode('utf-8')})
    db = connect(db_path)
    try:
        box = db.execute('SELECT id,batch_id FROM box WHERE id=?',
                         (contract['box_id'],)).fetchone()
        event = db.execute(
            "SELECT e.id,s.hash AS source_sha FROM raw_event e JOIN source_file s ON s.id=e.source_id "
            "WHERE e.box_id=? AND e.device=? AND e.kind='arrival' ORDER BY e.id LIMIT 1",
            (contract['box_id'], contract['device'])).fetchone()
        if box is None or event is None:
            raise ValueError('tariff_box_arrival_missing')
        payload = json.dumps(
            {'contract': contract, 'contract_sha256': hashlib.sha256(raw).hexdigest(),
             'box': dict(box), 'arrival': dict(event), 'sources': sources},
            sort_keys=True, separators=(',', ':'))
        with db:
            old = db.execute('SELECT payload FROM tariff_case WHERE id=?', (case_id,)).fetchone()
            if old and old['payload'] != payload:
                raise ValueError('tariff_case_conflict')
            db.execute('INSERT OR IGNORE INTO tariff_case VALUES (?,?)', (case_id, payload))
    finally:
        db.close()
    return {'case_id': case_id, 'sources': len(sources)}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def sha256_text(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def deterministic_id(prefix, payload):
    return prefix + '-' + hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    ).hexdigest()[:16]


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def temp_band(temp):
    if not VALID_TEMP.match(temp or ''):
        raise TariffError('invalid_temperature:' + str(temp))
    lo, hi = temp[:-1].split('-')
    return float(lo), float(hi)


def service_mode(temp):
    """Cold-chain vs room-temperature classification; the two may never be merged."""
    lo, hi = temp_band(temp)
    return 'cold' if hi <= 10 else 'room'


def round_half_up(value):
    """Integer-cent precision with half-up rounding (never banker's rounding)."""
    sign = -1 if value < 0 else 1
    return sign * int(abs(value) + 0.5)


def fuel_cents(base_cents, fuel_percent):
    return round_half_up(base_cents * fuel_percent / 100)


def total_cents(band):
    base = int(band['base_cents'])
    cold = int(band['cold_surcharge_cents'])
    fuel = fuel_cents(base, int(band['fuel_percent']))
    return {
        'base_cents': base,
        'cold_surcharge_cents': cold,
        'fuel_cents': fuel,
        'total_cents': base + cold + fuel,
    }


def load_case(db, case_id):
    row = db.execute('SELECT payload FROM tariff_case WHERE id=?', (case_id,)).fetchone()
    if row is None:
        raise TariffError('tariff_case_unknown')
    return json.loads(row['payload'])


def chargeable_weight(contract):
    """Max of actual weight and dimensional weight; dimensional divisor from the frozen contract."""
    actual = float(contract['actual_weight_kg'])
    dims = contract['dimensions_cm']
    divisor = float(contract.get('dimensional_divisor_cm3_per_kg', DIMENSIONAL_DIVISOR))
    dimensional = dims[0] * dims[1] * dims[2] / divisor
    return max(actual, dimensional)


# --------------------------------------------------------------------------- #
# raw parsing — HTML / CSV / signed addendum
# --------------------------------------------------------------------------- #

class _SectionParser(HTMLParser):
    """Extract <section>/<div data-* ...> tariff markers; no network access."""

    def __init__(self):
        super().__init__()
        self.sections = []

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if tag == 'section':
            self.sections.append({'section': data, 'divs': []})
        elif tag == 'div' and self.sections:
            self.sections[-1]['divs'].append(data)


def _parse_html(source):
    parser = _SectionParser()
    parser.feed(source['body'])
    if not parser.sections:
        raise TariffError('html_section_missing:' + source['name'])
    pages, bands = [], []
    for block in parser.sections:
        sec = block['section']
        carrier = sec.get('data-carrier')
        revision = int(sec['data-revision']) if sec.get('data-revision') is not None else None
        pages.append({
            'source_name': source['name'], 'sha256': source['sha256'], 'carrier': carrier,
            'revision': revision, 'page_kind': 'html', 'next_page': sec.get('data-next'),
        })
        for div in block['divs']:
            if div.get('data-kind'):
                # page-level surcharge marker: attach to every weight band of that service on this page
                for band in bands:
                    if band['source_name'] == source['name'] and band['service'] == div.get('data-service'):
                        kind = div['data-kind']
                        if kind == 'cold-surcharge':
                            band['cold_surcharge_cents'] = int(div['data-cents'])
                        elif kind == 'fuel-percent':
                            band['fuel_percent'] = int(div['data-value'])
                continue
            temp = div['data-temp']
            bands.append({
                'source_name': source['name'], 'sha256': source['sha256'], 'carrier': carrier,
                'service': div['data-service'], 'service_alias': None, 'temperature': temp,
                'mode': service_mode(temp),
                'min_kg': float(div['data-min-kg']), 'max_kg': float(div['data-max-kg']),
                'base_cents': int(div['data-base-cents']),
                'cold_surcharge_cents': 0, 'fuel_percent': 0, 'revision': revision,
            })
    return pages, bands


def _parse_csv(source):
    reader = csv.DictReader(io.StringIO(source['body']))
    pages = [{'source_name': source['name'], 'sha256': source['sha256'], 'carrier': None,
              'revision': None, 'page_kind': 'csv', 'next_page': None}]
    bands = []
    for row in reader:
        temp = row['temperature']
        bands.append({
            'source_name': source['name'], 'sha256': source['sha256'], 'carrier': row['carrier'],
            'service': row['service'], 'service_alias': None, 'temperature': temp,
            'mode': service_mode(temp),
            'min_kg': float(row['min_kg']), 'max_kg': float(row['max_kg']),
            'base_cents': int(row['base_cents']),
            'cold_surcharge_cents': int(row['cold_surcharge_cents']),
            'fuel_percent': int(row['fuel_percent']), 'revision': int(row['revision']),
        })
    if pages[0]['carrier'] is None and bands:
        pages[0]['carrier'] = bands[0]['carrier']
        pages[0]['revision'] = bands[0]['revision']
    return pages, bands


def _parse_addendum(source):
    doc = json.loads(source['body'])
    pages = [{'source_name': source['name'], 'sha256': source['sha256'], 'carrier': doc.get('carrier'),
              'revision': None, 'page_kind': 'addendum', 'next_page': None}]
    return pages, doc


# --------------------------------------------------------------------------- #
# extraction, page-chain verification, identity merge and graph validation
# --------------------------------------------------------------------------- #

def _record_issue(db, case_id, blocking, code, detail):
    db.execute('INSERT INTO tariff_issue(case_id,blocking,code,detail) VALUES (?,?,?,?)',
               (case_id, 1 if blocking else 0, code, detail))


def extract_sources(db, case_id):
    """Parse every frozen source, verify the HTML page chain and persist raw extracts.

    Re-running rebuilds derived rows; the frozen ``tariff_case`` bytes are never touched.
    """
    case = load_case(db, case_id)
    sources = {s['name']: s for s in case['sources']}
    db.execute('DELETE FROM tariff_page WHERE case_id=?', (case_id,))
    db.execute('DELETE FROM tariff_band WHERE case_id=?', (case_id,))
    db.execute('DELETE FROM tariff_issue WHERE case_id=?', (case_id,))

    pages, bands, addendum, addendum_name, issues = [], [], None, None, []

    def issue(blocking, code, detail):
        issues.append({'blocking': blocking, 'code': code, 'detail': detail})
        _record_issue(db, case_id, blocking, code, detail)

    for name in case['contract']['source_pages']:
        source = sources[name]
        suffix = Path(name).suffix
        try:
            if suffix == '.html':
                p, b = _parse_html(source)
            elif suffix == '.csv':
                p, b = _parse_csv(source)
            elif suffix == '.json':
                p, addendum = _parse_addendum(source)
                addendum_name = name
                b = []
            else:
                raise TariffError('unsupported_source:' + name)
        except (TariffError, KeyError, ValueError, json.JSONDecodeError) as exc:
            issue(True, 'source_parse_error', f'{name}: {exc}')
            continue
        pages.extend(p)
        bands.extend(b)

    # ---- HTML pagination chain: follow data-next from the first HTML page, no gaps/cycles ----
    html_pages = {p['source_name']: p for p in pages if p['page_kind'] == 'html'}
    if html_pages:
        ordered, seen = [], set()
        listed = [n for n in case['contract']['source_pages'] if n in html_pages]
        cursor = listed[0] if listed else next(iter(html_pages))
        while cursor:
            if cursor not in html_pages:
                issue(True, 'pagination_missing_page', f'chain references unknown page {cursor}')
                break
            if cursor in seen:
                issue(True, 'pagination_cycle', f'page chain cycles at {cursor}')
                break
            seen.add(cursor)
            ordered.append(html_pages[cursor])
            cursor = html_pages[cursor]['next_page']
        orphan = sorted(set(html_pages) - seen)
        if orphan:
            issue(True, 'pagination_orphan_page', 'pages not reachable from chain: ' + ','.join(orphan))
        # ---- cross-page revision consistency for one carrier's chain ----
        revisions = {(p['carrier'], p['revision']) for p in ordered}
        carriers = {p['carrier'] for p in ordered}
        if len(carriers) == 1 and len(revisions) > 1:
            issue(True, 'cross_page_revision_mismatch',
                  '; '.join(f"{p['source_name']}=rev{p['revision']}" for p in ordered))

    # ---- addendum signature/alias/temperature/date verification ----
    addendum_check = None
    if addendum is not None:
        addendum_check = _verify_addendum(addendum, addendum_name, sources[addendum_name],
                                          case, issue)

    # ---- identity merge: identical (carrier,service,temp,weight interval) rows ----
    merged = {}
    for band in bands:
        key = (band['carrier'], band['service'], band['temperature'], band['min_kg'], band['max_kg'])
        if key not in merged:
            merged[key] = dict(band)
            merged[key]['source_names'] = [band['source_name']]
            continue
        kept = merged[key]
        kept['source_names'].append(band['source_name'])
        same = all(kept[f] == band[f] for f in
                   ('base_cents', 'cold_surcharge_cents', 'fuel_percent', 'revision'))
        if same:
            issue(False, 'duplicate_revision',
                  f'{band["carrier"]}/{band["service"]} {band["min_kg"]}-{band["max_kg"]}kg '
                  f'repeated in {band["source_name"]}; sources retained')
        else:
            issue(True, 'cross_page_conflict_price',
                  f'{key} differs between {kept["source_names"]}: kept both, no last-row/min-price ruling')
            kept.setdefault('conflicts', []).append(band)

    # ---- graph assembly per service identity ----
    identities = {}
    for band in merged.values():
        ident = (band['carrier'], band['service'], band['temperature'])
        identities.setdefault(ident, {'carrier': band['carrier'], 'service': band['service'],
                                      'temperature': band['temperature'], 'mode': band['mode'],
                                      'bands': []})
        identities[ident]['bands'].append(band)

    for ident, node in identities.items():
        node['bands'].sort(key=lambda x: (x['min_kg'], x['max_kg']))
        for band in node['bands']:
            band['pricing'] = total_cents(band)
        # interval coverage: no overlaps and no gaps between consecutive half-open [min,max) bands
        for first, second in zip(node['bands'], node['bands'][1:]):
            if second['min_kg'] < first['max_kg']:
                issue(True, 'overlapping_weight_band',
                      f'{ident}: {first["min_kg"]}-{first["max_kg"]} overlaps '
                      f'{second["min_kg"]}-{second["max_kg"]}; both isolated')
            elif second['min_kg'] > first['max_kg']:
                issue(True, 'weight_band_gap',
                      f'{ident}: no legal price between {first["max_kg"]}kg and {second["min_kg"]}kg')

    # ---- scale limits: up to 4 carriers / 30 pages / 100 bands ----
    if len({b['carrier'] for b in bands}) > MAX_CARRIERS:
        issue(True, 'carrier_limit_exceeded', f'more than {MAX_CARRIERS} carriers')
    if len(pages) > MAX_PAGES:
        issue(True, 'page_limit_exceeded', f'more than {MAX_PAGES} pages')
    if len(bands) > MAX_BANDS:
        issue(True, 'band_limit_exceeded', f'more than {MAX_BANDS} weight bands')

    for page in pages:
        db.execute('INSERT INTO tariff_page(case_id,source_name,sha256,carrier,revision,page_kind,next_page)'
                   ' VALUES (?,?,?,?,?,?,?)',
                   (case_id, page['source_name'], page['sha256'], page['carrier'], page['revision'],
                    page['page_kind'], page['next_page']))
    for band in bands:
        db.execute('INSERT INTO tariff_band(case_id,source_name,sha256,carrier,service,service_alias,'
                   'temperature,mode,min_kg,max_kg,base_cents,cold_surcharge_cents,fuel_percent,revision)'
                   ' VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (case_id, band['source_name'], band['sha256'], band['carrier'], band['service'],
                    band['service_alias'], band['temperature'], band['mode'], band['min_kg'],
                    band['max_kg'], band['base_cents'], band['cold_surcharge_cents'],
                    band['fuel_percent'], band['revision']))

    return {'pages': pages, 'identities': identities, 'addendum': addendum,
            'addendum_check': addendum_check, 'issues': issues, 'case': case}


def _verify_addendum(addendum, addendum_name, addendum_source, case, issue):
    """A signed addendum is valid only with signature, verified alias, matching temperature and live dates."""
    result = {'valid': False, 'reasons': [], 'doc': addendum,
              'source_name': addendum_name, 'sha256': addendum_source['sha256']}
    if not addendum.get('signature'):
        result['reasons'].append('addendum_unsigned')
    alias_map = addendum.get('service_alias') or {}
    if len(alias_map) != 1:
        result['reasons'].append('addendum_alias_invalid')
    service_time = parse_time(case['contract']['service_time'])
    try:
        effective = parse_time(addendum['effective'])
        expiry = parse_time(addendum['expiry'])
        if not (effective <= service_time < expiry):
            result['reasons'].append('addendum_not_in_effect')
    except (KeyError, ValueError):
        result['reasons'].append('addendum_date_invalid')
    temp = addendum.get('temperature', '')
    try:
        if service_mode(temp) != 'cold':
            result['reasons'].append('addendum_temperature_mismatch')
    except TariffError:
        result['reasons'].append('addendum_temperature_mismatch')
    # alias must point at a real public service of the same carrier and the same cold temperature
    for alias, target in alias_map.items():
        if not re.match(r'^[A-Z0-9-]+$', alias) or not re.match(r'^[A-Z0-9-]+$', str(target)):
            result['reasons'].append('addendum_alias_invalid')
        result['alias'] = alias
        result['target'] = target
    if 'alias' not in result:
        result['alias'] = result['target'] = None
    result['valid'] = not result['reasons']
    if not result['valid']:
        # anomaly is quarantined; public_tariff route remains buildable, signed_addendum route is blocked
        issue(True, 'addendum_invalid', '; '.join(result['reasons']))
    return result


# --------------------------------------------------------------------------- #
# candidate master-data versions
# --------------------------------------------------------------------------- #

def _public_graph(extraction):
    """public_tariff: full public pages only; room-temperature stays a separate identity."""
    return [_identity_payload(node)
            for _, node in sorted(extraction['identities'].items())]


def _signed_graph(extraction):
    """signed_addendum: validated addendum exclusively replaces the matching A weight band."""
    check = extraction['addendum_check']
    if check is None:
        raise TariffError('signed_addendum_unavailable:addendum_missing')
    if not check['valid']:
        # recorded as a blocking addendum_invalid issue; the version gate reports the stable code
        # while the concrete reasons stay in the issue detail
        raise TariffError('version_validation_failed:addendum_invalid')
    doc = check['doc']
    alias, target = check['alias'], check['target']
    if doc['carrier'] not in {n['carrier'] for n in extraction['pages']}:
        raise TariffError('addendum_carrier_unknown')
    graph, replaced = [], []
    matched = False
    for ident, node in sorted(extraction['identities'].items()):
        if ident != (doc['carrier'], target, doc['temperature']):
            graph.append(_identity_payload(node))
            continue
        # same identity only because signed alias AND 2-8C storage were both verified
        kept_bands, addendum_band = [], None
        for band in node['bands']:
            if band['min_kg'] == float(doc['min_kg']) and band['max_kg'] == float(doc['max_kg']):
                matched = True
                addendum_band = {
                    'source_names': [check['source_name']],
                    'sha256': check['sha256'], 'carrier': doc['carrier'],
                    'service': target, 'service_alias': alias, 'temperature': doc['temperature'],
                    'mode': 'cold', 'min_kg': float(doc['min_kg']), 'max_kg': float(doc['max_kg']),
                    'base_cents': int(doc['base_cents']),
                    'cold_surcharge_cents': int(doc['cold_surcharge_cents']),
                    'fuel_percent': int(doc['fuel_percent']), 'revision': None,
                }
                addendum_band['pricing'] = total_cents(addendum_band)
                replaced.append({'service': target, 'alias': alias,
                                 'min_kg': addendum_band['min_kg'], 'max_kg': addendum_band['max_kg'],
                                 'public_band': band['pricing'],
                                 'addendum_band': addendum_band['pricing'],
                                 'source_sha256': check['sha256']})
            else:
                kept_bands.append(band)
        new_node = {'carrier': node['carrier'], 'service': node['service'],
                    'service_aliases': sorted(set(node.get('service_aliases', []) + [alias])),
                    'temperature': node['temperature'], 'mode': node['mode'],
                    'bands': [_band_payload(b) for b in kept_bands]
                             + ([_band_payload(addendum_band)] if addendum_band else [])}
        new_node['bands'].sort(key=lambda x: (x['min_kg'], x['max_kg']))
        graph.append(new_node)
    if not matched:
        raise TariffError('addendum_band_not_found')
    return graph, replaced


def _identity_payload(node):
    return {
        'carrier': node['carrier'], 'service': node['service'],
        'service_aliases': node.get('service_aliases', []),
        'temperature': node['temperature'], 'mode': node['mode'],
        'bands': [_band_payload(b) for b in node['bands']],
    }


def _band_payload(band):
    payload = {k: band[k] for k in
               ('source_names', 'sha256', 'carrier', 'service', 'service_alias', 'temperature',
                'mode', 'min_kg', 'max_kg', 'base_cents', 'cold_surcharge_cents',
                'fuel_percent', 'revision', 'pricing')}
    return payload


def _validate_graph(graph, issues, authority, target_weight_kg=None):
    """Whole-graph gate: any blocking issue or any identity with overlap/gap/conflict blocks publish.

    ``addendum_invalid`` is authority-scoped: it blocks the signed-addendum route (raised in
    ``_signed_graph``) but must never block the public-tariff route.
    """
    blocking = [i for i in issues if i['blocking'] and i['code'] != 'addendum_invalid']
    if blocking:
        raise TariffError('version_validation_failed:' + ','.join(
            sorted({i['code'] for i in blocking})))
    if not graph:
        raise TariffError('version_empty_graph')
    for node in graph:
        if not node['bands']:
            raise TariffError('version_identity_without_band:' + node['service'])
        for first, second in zip(node['bands'], node['bands'][1:]):
            if second['min_kg'] < first['max_kg'] or second['min_kg'] > first['max_kg']:
                raise TariffError('version_interval_not_covered:' + node['service'])
        if any(b.get('conflicts') for b in node['bands']):
            raise TariffError('version_unresolved_conflict:' + node['service'])
    # a single first page cannot go live: at least one cold service must legally price the real box
    if target_weight_kg is not None:
        covered = any(
            node['mode'] == 'cold'
            and any(b['min_kg'] <= target_weight_kg < b['max_kg'] for b in node['bands'])
            for node in graph)
        if not covered:
            raise TariffError('version_box_weight_uncovered:' + str(target_weight_kg))


def build_version(db_path, case_id, authority):
    """Extract and validate the frozen sources, then freeze one whole-graph candidate version."""
    if authority not in ALLOWED_AUTHORITIES:
        raise TariffError('unknown_authority:' + str(authority))
    db = connect(db_path)
    try:
        with db:
            extraction = extract_sources(db, case_id)
            case = extraction['case']
            if authority not in case['contract'].get('allowed_authorities', []):
                raise TariffError('authority_not_authorized:' + authority)
            replacements = []
            if authority == 'public_tariff':
                graph = _public_graph(extraction)
            else:
                graph, replacements = _signed_graph(extraction)
            _validate_graph(graph, extraction['issues'], authority,
                            target_weight_kg=chargeable_weight(case['contract']))
            sources_sha = [{'name': s['name'], 'sha256': s['sha256']}
                           for s in case['sources']]
            payload = {
                'case_id': case_id, 'authority': authority,
                'contract_version': case['contract'].get('version'),
                'box_id': case['contract']['box_id'],
                'source_sha256': sources_sha,
                'graph': graph, 'addendum_replacements': replacements,
                'issues': [{'code': i['code'], 'blocking': i['blocking'], 'detail': i['detail']}
                           for i in extraction['issues']],
            }
            version_id = deterministic_id('ver', payload)
            payload['version_id'] = version_id
            db.execute('INSERT OR IGNORE INTO tariff_version(id,case_id,authority,payload,created_at)'
                       ' VALUES (?,?,?,?,?)',
                       (version_id, case_id, authority,
                        json.dumps(payload, ensure_ascii=False, sort_keys=True), now_iso()))
        return version_id
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# version-fenced publication with a mock downstream rate master
# --------------------------------------------------------------------------- #

class MockRateMaster:
    """In-process stand-in for the downstream rate-master endpoint (local simulation only).

    Behaviour switches for failure-injection tests:
      * ``partial_services``: endpoint receives only part of the graph -> rejected, no ACK.
      * ``lose_ack``: the endpoint persisted but the ACK is lost -> caller retries, idempotent.
    """

    def __init__(self, target='mock-rate-master', partial_services=False, lose_ack=False):
        self.target = target
        self.partial_services = partial_services
        self.lose_ack = lose_ack
        self.received = {}

    def push(self, envelope):
        version_id = envelope['version_id']
        pushed = dict(envelope)
        if self.partial_services and pushed['services']:
            pushed = dict(pushed)
            pushed['services'] = pushed['services'][:1]
        if len(pushed['services']) != envelope['service_count']:
            return {'acked': False, 'reason': 'partial_service_set',
                    'expected': envelope['service_count'], 'got': len(pushed['services'])}
        # idempotent: re-pushing an ACKed version returns the same receipt
        if version_id in self.received:
            receipt = self.received[version_id]
        else:
            receipt = deterministic_id('rcpt', envelope)
            self.received[version_id] = receipt
        if self.lose_ack:
            return {'acked': False, 'reason': 'ack_lost', 'receipt': receipt}
        return {'acked': True, 'receipt': receipt, 'target': self.target,
                'version_id': version_id, 'service_count': envelope['service_count']}


def publish(db_path, case_id, authority, endpoint=None):
    """Publish a fully validated version behind a version fence.

    Whole graph or nothing: a partial push, a lost ACK or a concurrent worker leaves the
    previous current version queryable. Only one ACKed current publication exists per case.
    """
    endpoint = endpoint or MockRateMaster()
    db = connect(db_path)
    try:
        case = load_case(db, case_id)
        target = case['contract']['publish_target']
        try:
            db.execute('BEGIN IMMEDIATE')
        except sqlite3.OperationalError:
            raise TariffError('publish_concurrent')
        row = db.execute('SELECT id,payload FROM tariff_version WHERE case_id=? AND authority=?',
                         (case_id, authority)).fetchone()
        if row is None:
            db.commit()
            raise TariffError('version_not_built:' + authority)
        version_id, version_payload = row['id'], json.loads(row['payload'])
        envelope = {
            'target': target, 'case_id': case_id, 'version_id': version_id,
            'authority': authority, 'service_count': len(version_payload['graph']),
            'services': version_payload['graph'],
        }
        ack = endpoint.push(envelope)
        if not ack.get('acked'):
            # no half-published master: do not record a current row, old version stays current
            db.execute('INSERT INTO tariff_publication(id,case_id,version_id,target,receipt,acked,created_at)'
                       ' VALUES (?,?,?,?,?,?,?)',
                       (deterministic_id('pub-nack', [version_id, json.dumps(ack, sort_keys=True)]),
                        case_id, version_id, target, json.dumps(ack, ensure_ascii=False), 0, now_iso()))
            db.commit()
            raise TariffError('publish_rejected:' + str(ack.get('reason')))
        receipt = ack['receipt']
        existing = db.execute(
            'SELECT id FROM tariff_publication WHERE case_id=? AND version_id=? AND acked=1',
            (case_id, version_id)).fetchone()
        if existing:
            db.commit()  # idempotent retry after ACK loss
            return {'version_id': version_id, 'receipt': receipt, 'idempotent': True}
        previous = db.execute(
            'SELECT version_id FROM tariff_publication WHERE case_id=? AND acked=1 AND superseded=0',
            (case_id,)).fetchone()
        # whole-version fence inside one transaction: retire the old current row, then make the
        # new ACKed version current. The historical row (and old quotes referencing it) is retained.
        try:
            if previous:
                db.execute('UPDATE tariff_publication SET superseded=1 '
                           'WHERE case_id=? AND acked=1 AND superseded=0', (case_id,))
            db.execute('INSERT INTO tariff_publication(id,case_id,version_id,target,receipt,acked,superseded,created_at)'
                       ' VALUES (?,?,?,?,?,?,0,?)',
                       (deterministic_id('pub', [case_id, version_id, receipt]),
                        case_id, version_id, target, receipt, 1, now_iso()))
        except sqlite3.IntegrityError as exc:
            db.rollback()
            raise TariffError('publish_concurrent:' + str(exc))
        if previous and previous['version_id'] != version_id:
            _audit_diff(db, case_id, previous['version_id'], version_id)
        db.commit()
        return {'version_id': version_id, 'receipt': receipt, 'idempotent': False,
                'superseded': previous['version_id'] if previous else None}
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# customer quotes — only from ACKed published version IDs
# --------------------------------------------------------------------------- #

def _band_for_weight(node, weight_kg):
    hits = [b for b in node['bands'] if b['min_kg'] <= weight_kg < b['max_kg']]
    if len(hits) > 1:
        raise TariffError('quote_multiple_prices:' + node['service'])
    if not hits:
        return None
    return hits[0]


def quote(db_path, case_id):
    """Quote the real box against the current ACKed master version; never re-read web pages."""
    db = connect(db_path)
    try:
        case = load_case(db, case_id)
        current = db.execute(
            'SELECT version_id FROM tariff_publication WHERE case_id=? AND acked=1 AND superseded=0',
            (case_id,)).fetchone()
        if current is None:
            raise TariffError('no_published_version')
        version_id = current['version_id']
        version = json.loads(db.execute('SELECT payload FROM tariff_version WHERE id=?',
                                        (version_id,)).fetchone()['payload'])
        weight = chargeable_weight(case['contract'])
        lines, room_lines = [], []
        for node in version['graph']:
            band = _band_for_weight(node, weight)
            if band is None:
                continue
            line = {'carrier': node['carrier'], 'service': node['service'],
                    'service_aliases': node.get('service_aliases', []),
                    'temperature': node['temperature'], 'mode': node['mode'],
                    'matched_band_kg': [band['min_kg'], band['max_kg']],
                    'source_names': band['source_names'], 'source_sha256': band['sha256'],
                    **band['pricing']}
            (room_lines if node['mode'] == 'room' else lines).append(line)
        if not lines:
            raise TariffError('quote_no_cold_service_covered')
        # deterministic lowest available cold quote; ties broken by carrier then service name
        best = sorted(lines, key=lambda l: (l['total_cents'], l['carrier'], l['service']))[0]
        payload = {'case_id': case_id, 'box_id': case['contract']['box_id'],
                   'version_id': version_id, 'authority': version['authority'],
                   'chargeable_kg': weight,
                   'actual_weight_kg': float(case['contract']['actual_weight_kg']),
                   'dimensional_kg': case['contract']['dimensions_cm'][0]
                                     * case['contract']['dimensions_cm'][1]
                                     * case['contract']['dimensions_cm'][2]
                                     / float(case['contract'].get('dimensional_divisor_cm3_per_kg',
                                                                  DIMENSIONAL_DIVISOR)),
                   'cold_quotes': lines, 'room_temperature_quotes': room_lines,
                   'selected': best}
        with db:
            db.execute('INSERT INTO tariff_quote(case_id,box_id,version_id,chargeable_kg,payload,created_at)'
                       ' VALUES (?,?,?,?,?,?)',
                       (case_id, payload['box_id'], version_id, weight,
                        json.dumps(payload, ensure_ascii=False, sort_keys=True), now_iso()))
        return payload
    finally:
        db.close()


def list_quotes(db_path, case_id):
    db = connect(db_path)
    try:
        rows = [json.loads(r['payload']) for r in db.execute(
            'SELECT payload FROM tariff_quote WHERE case_id=? ORDER BY id', (case_id,))]
        return rows
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# correction audit: new versions and diffs, never rewritten history
# --------------------------------------------------------------------------- #

def _audit_diff(db, case_id, from_version_id, to_version_id):
    left = json.loads(db.execute('SELECT payload FROM tariff_version WHERE id=?',
                                 (from_version_id,)).fetchone()['payload'])
    right = json.loads(db.execute('SELECT payload FROM tariff_version WHERE id=?',
                                  (to_version_id,)).fetchone()['payload'])

    def index(version):
        out = {}
        for node in version['graph']:
            for band in node['bands']:
                out[(node['carrier'], node['service'], node['temperature'],
                     band['min_kg'], band['max_kg'])] = band['pricing']['total_cents']
        return out

    before, after = index(left), index(right)
    changes = []
    for key in sorted(set(before) | set(after)):
        old_total, new_total = before.get(key), after.get(key)
        if old_total != new_total:
            changes.append({'carrier': key[0], 'service': key[1], 'temperature': key[2],
                            'band_kg': [key[3], key[4]], 'total_cents_before': old_total,
                            'total_cents_after': new_total,
                            'delta_cents': None if old_total is None or new_total is None
                            else new_total - old_total})
    payload = {'case_id': case_id, 'from_version_id': from_version_id,
               'to_version_id': to_version_id,
               'from_authority': left['authority'], 'to_authority': right['authority'],
               'changes': changes}
    db.execute('INSERT INTO tariff_audit(case_id,from_version_id,to_version_id,payload,created_at)'
               ' VALUES (?,?,?,?,?)',
               (case_id, from_version_id, to_version_id,
                json.dumps(payload, ensure_ascii=False, sort_keys=True), now_iso()))
    return payload


def audit_trail(db_path, case_id):
    db = connect(db_path)
    try:
        return [json.loads(r['payload']) for r in db.execute(
            'SELECT payload FROM tariff_audit WHERE case_id=? ORDER BY id', (case_id,))]
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# JSON / Markdown reports
# --------------------------------------------------------------------------- #

def write_reports(db_path, case_id, out_dir):
    """Emit rate-map, diff and quote reports (JSON + Markdown) from stored, frozen state."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    db = connect(db_path)
    try:
        case = load_case(db, case_id)
        versions = [dict(r) for r in db.execute(
            'SELECT id,authority,payload,created_at FROM tariff_version WHERE case_id=? ORDER BY authority',
            (case_id,))]
        publications = [dict(r) for r in db.execute(
            'SELECT id,version_id,target,receipt,acked,created_at FROM tariff_publication '
            'WHERE case_id=? ORDER BY id', (case_id,))]
        issues = [dict(r) for r in db.execute(
            'SELECT blocking,code,detail FROM tariff_issue WHERE case_id=? ORDER BY id', (case_id,))]
        quotes = list_quotes(db_path, case_id)
        audits = audit_trail(db_path, case_id)
    finally:
        db.close()

    map_payload = {'case_id': case_id, 'box_id': case['contract']['box_id'],
                   'sources': case['sources'], 'versions': versions,
                   'publications': publications, 'issues': issues}
    map_json = out_dir / 'rate-map.json'
    map_json.write_text(json.dumps(map_payload, ensure_ascii=False, indent=2, sort_keys=True),
                        encoding='utf-8')
    lines = ['# 承运商费率图（离线冻结来源）', '',
             f"- 案例：{case_id}；箱：{case['contract']['box_id']}",
             f"- 冻结来源：{', '.join(s['name'] for s in case['sources'])}", '']
    for ver in versions:
        payload = json.loads(ver['payload'])
        lines.append(f"## 版本 {ver['id']}（权威：{ver['authority']}）")
        for node in payload['graph']:
            alias = f"，别名 {','.join(node['service_aliases'])}" if node.get('service_aliases') else ''
            lines.append(f"### {node['carrier']} / {node['service']}{alias} "
                         f"（{node['temperature']}，{node['mode']}）")
            lines.append('| 重量区间 kg | 基价(分) | 冷链附加(分) | 燃油(分) | 合计(分) | 来源 |')
            lines.append('|---|---:|---:|---:|---:|---|')
            for band in node['bands']:
                p = band['pricing']
                lines.append(f"| {band['min_kg']:g}–{band['max_kg']:g} | {p['base_cents']} | "
                             f"{p['cold_surcharge_cents']} | {p['fuel_cents']} | {p['total_cents']} | "
                             f"{','.join(band['source_names'])} |")
            lines.append('')
    if issues:
        lines.append('## 校验问题与隔离项')
        for it in issues:
            lines.append(f"- [{'阻断' if it['blocking'] else '提示'}] {it['code']}: {it['detail']}")
    (out_dir / 'rate-map.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')

    diff_payload = {'case_id': case_id, 'audits': audits}
    (out_dir / 'rate-diff.json').write_text(
        json.dumps(diff_payload, ensure_ascii=False, indent=2, sort_keys=True), encoding='utf-8')
    dlines = ['# 版本差额审计', '']
    for audit in audits:
        dlines.append(f"## {audit['from_version_id']} → {audit['to_version_id']} "
                      f"（{audit['from_authority']} → {audit['to_authority']}）")
        dlines.append('| 承运商 | 服务 | 储温 | 区间 kg | 旧价(分) | 新价(分) | 差额(分) |')
        dlines.append('|---|---|---|---|---:|---:|---:|')
        for ch in audit['changes']:
            dlines.append(f"| {ch['carrier']} | {ch['service']} | {ch['temperature']} | "
                          f"{ch['band_kg'][0]:g}–{ch['band_kg'][1]:g} | {ch['total_cents_before']} | "
                          f"{ch['total_cents_after']} | {ch['delta_cents']} |")
        dlines.append('')
    (out_dir / 'rate-diff.md').write_text('\n'.join(dlines) + '\n', encoding='utf-8')

    (out_dir / 'quotes.json').write_text(
        json.dumps({'case_id': case_id, 'quotes': quotes}, ensure_ascii=False, indent=2,
                   sort_keys=True), encoding='utf-8')
    qlines = ['# 客户报价（仅引用已 ACK 的发布版本）', '']
    for q in quotes:
        qlines.append(f"## 箱 {q['box_id']} @ 版本 {q['version_id']}（{q['authority']}）")
        qlines.append(f"- 实重 {q['actual_weight_kg']:g}kg；体积重 {q['dimensional_kg']:g}kg；"
                      f"计费重量 {q['chargeable_kg']:g}kg")
        for l in q['cold_quotes']:
            qlines.append(f"- 冷藏 {l['carrier']}/{l['service']} {l['temperature']} "
                          f"{l['matched_band_kg'][0]:g}–{l['matched_band_kg'][1]:g}kg："
                          f"{l['total_cents']} 分"
                          + (' ★最低' if l is q['selected'] else ''))
        for l in q['room_temperature_quotes']:
            qlines.append(f"- 室温（单列，不与冷藏合并）{l['carrier']}/{l['service']} "
                          f"{l['temperature']}：{l['total_cents']} 分")
        qlines.append('')
    (out_dir / 'quotes.md').write_text('\n'.join(qlines) + '\n', encoding='utf-8')
    return {p.name: str(p) for p in (out_dir / 'rate-map.json', out_dir / 'rate-map.md',
                                     out_dir / 'rate-diff.json', out_dir / 'rate-diff.md',
                                     out_dir / 'quotes.json', out_dir / 'quotes.md')}
