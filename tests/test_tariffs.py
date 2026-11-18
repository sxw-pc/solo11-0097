"""End-to-end tests for offline tariff extraction, identity merge, version fence and quotes."""
import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from coldhandoff.__main__ import init
from coldhandoff.ingest import ingest
from coldhandoff.store import connect
from coldhandoff import tariffs
from coldhandoff.tariffs import (
    MockRateMaster, TariffError, build_version, chargeable_weight, publish, quote,
    register, write_reports,
)

FIX = Path(__file__).resolve().parents[1] / 'fixtures'
FROZEN = ['carrier-a-index.html', 'carrier-a-2.html', 'carrier-b.csv', 'signed-addendum.json']


# --------------------------------------------------------------------------- #
# fixture helpers
# --------------------------------------------------------------------------- #

def seed_case(tmp_path, case_id='rates-1', sources=None, contract_name='tariff-contract.json',
              db_name='tariff.db'):
    """Copy (or mutate) the frozen sources into an isolated dir and register against a real arrival."""
    src_dir = tmp_path / 'sources'
    src_dir.mkdir()
    names = sources if sources is not None else FROZEN
    for name in names:
        shutil.copy(FIX / name, src_dir / name)
    contract = json.loads((FIX / contract_name).read_text())
    if sources is not None:
        contract['source_pages'] = names
    contract_path = tmp_path / 'tariff-contract.json'
    contract_path.write_text(json.dumps(contract), encoding='utf-8')
    db_path = tmp_path / db_name
    init(db_path, 'batch-t', 'box-A')
    ingest(FIX / 'tariff-events.jsonl', db_path)
    register(db_path, case_id, contract_path, src_dir)
    return db_path, src_dir, contract_path, contract


def refreeze_case(db_path, case_id, contract_path, src_dir):
    """Re-freeze mutated source bytes for the same case (raw bytes changed deliberately)."""
    contract = json.loads(Path(contract_path).read_text())
    sources = []
    for name in contract['source_pages']:
        body = (Path(src_dir) / name).read_bytes()
        sources.append({'name': name, 'sha256': __import__('hashlib').sha256(body).hexdigest(),
                        'body': body.decode('utf-8')})
    db = connect(db_path)
    box = db.execute('SELECT id,batch_id FROM box WHERE id=?',
                     (contract['box_id'],)).fetchone()
    event = db.execute(
        "SELECT e.id,s.hash AS source_sha FROM raw_event e JOIN source_file s ON s.id=e.source_id "
        "WHERE e.box_id=? AND e.device=? AND e.kind='arrival' ORDER BY e.id LIMIT 1",
        (contract['box_id'], contract['device'])).fetchone()
    raw = Path(contract_path).read_bytes()
    import hashlib
    payload = json.dumps(
        {'contract': contract, 'contract_sha256': hashlib.sha256(raw).hexdigest(),
         'box': dict(box), 'arrival': dict(event), 'sources': sources},
        sort_keys=True, separators=(',', ':'))
    with db:
        db.execute('UPDATE tariff_case SET payload=? WHERE id=?', (payload, case_id))
    db.close()


def published_version(db_path, authority, endpoint=None):
    version_id = build_version(db_path, 'rates-1', authority)
    receipt = publish(db_path, 'rates-1', authority, endpoint)
    return version_id, receipt


def graph_of(db_path, version_id):
    db = connect(db_path)
    payload = json.loads(db.execute('SELECT payload FROM tariff_version WHERE id=?',
                                    (version_id,)).fetchone()['payload'])
    db.close()
    return payload


def node(graph, carrier, service):
    hits = [n for n in graph if n['carrier'] == carrier and n['service'] == service]
    assert len(hits) == 1
    return hits[0]


def band(node, min_kg):
    hits = [b for b in node['bands'] if b['min_kg'] == min_kg]
    assert len(hits) == 1
    return hits[0]


# --------------------------------------------------------------------------- #
# happy path: extraction, page chain, identity merge, integer-cent pricing
# --------------------------------------------------------------------------- #

def test_chargeable_weight_uses_dimensional_weight():
    contract = {'actual_weight_kg': 4, 'dimensions_cm': [40, 30, 25],
                'dimensional_divisor_cm3_per_kg': 5000}
    assert chargeable_weight(contract) == 6.0  # 40*30*25/5000 = 6 > 4


def test_chargeable_weight_takes_actual_when_heavier():
    contract = {'actual_weight_kg': 8, 'dimensions_cm': [10, 10, 10],
                'dimensional_divisor_cm3_per_kg': 5000}
    assert chargeable_weight(contract) == 8.0


def test_fuel_surcharge_keeps_integer_cent_half_up_precision():
    # 15% of 655 = 98.25 -> 98; half-up on .5: 10% of 555 = 55.5 -> 56 (never banker's 55)
    assert tariffs.fuel_cents(655, 15) == 98
    assert tariffs.fuel_cents(555, 10) == 56
    assert tariffs.fuel_cents(500, 10) == 50
    assert tariffs.total_cents({'base_cents': 500, 'cold_surcharge_cents': 300,
                                'fuel_percent': 10})['total_cents'] == 850


def test_weight_band_is_half_open_so_boundary_hits_upper_band():
    # exactly 5kg must land in [5,10), not [0,5)
    node = {'bands': [
        {'min_kg': 0.0, 'max_kg': 5.0},
        {'min_kg': 5.0, 'max_kg': 10.0}]}
    assert tariffs._band_for_weight(node, 5.0)['min_kg'] == 5.0
    assert tariffs._band_for_weight(node, 4.999)['min_kg'] == 0.0


def test_public_tariff_extracts_both_pages_and_verifies_chain(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    version_id = build_version(db_path, 'rates-1', 'public_tariff')
    payload = graph_of(db_path, version_id)
    assert payload['authority'] == 'public_tariff'
    # two carriers, three distinct service identities (COLD24, ROOM24, B/FROZEN-24)
    assert {(n['carrier'], n['service']) for n in payload['graph']} == \
           {('A', 'COLD24'), ('A', 'ROOM24'), ('B', 'FROZEN-24')}
    cold_a = node(payload['graph'], 'A', 'COLD24')
    assert [b['min_kg'] for b in cold_a['bands']] == [0.0, 5.0]
    first, second = cold_a['bands']
    assert first['pricing']['total_cents'] == 400
    # 500 base + 300 cold surcharge + 10% fuel (50) = 850, integer cents
    assert second['pricing'] == {'base_cents': 500, 'cold_surcharge_cents': 300,
                                 'fuel_cents': 50, 'total_cents': 850}
    # page chain and same revision across both A pages
    db = connect(db_path)
    pages = {r['source_name']: r for r in db.execute(
        "SELECT * FROM tariff_page WHERE case_id='rates-1' AND page_kind='html'")}
    assert pages['carrier-a-index.html']['next_page'] == 'carrier-a-2.html'
    assert pages['carrier-a-2.html']['next_page'] is None
    assert {p['revision'] for p in pages.values()} == {17}
    db.close()


def test_room_and_cold_never_merge(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    version_id = build_version(db_path, 'rates-1', 'public_tariff')
    payload = graph_of(db_path, version_id)
    room = node(payload['graph'], 'A', 'ROOM24')
    cold = node(payload['graph'], 'A', 'COLD24')
    assert room['mode'] == 'room' and cold['mode'] == 'cold'
    assert room['temperature'] == '15-25C' and cold['temperature'] == '2-8C'
    # room service is a standalone identity even though both are 24h services
    assert room['service'] != cold['service']
    # the raw extracted bands keep the two storage temperatures on separate identity rows
    db = connect(db_path)
    idents = {(r['service'], r['temperature'], r['mode']) for r in db.execute(
        "SELECT service,temperature,mode FROM tariff_band WHERE case_id='rates-1'")}
    assert ('COLD24', '2-8C', 'cold') in idents
    assert ('ROOM24', '15-25C', 'room') in idents
    db.close()


def test_carrier_b_is_separate_identity(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    version_id = build_version(db_path, 'rates-1', 'public_tariff')
    payload = graph_of(db_path, version_id)
    b = node(payload['graph'], 'B', 'FROZEN-24')
    assert b['mode'] == 'cold'
    assert band(b, 0.0)['pricing'] == {'base_cents': 650, 'cold_surcharge_cents': 100,
                                       'fuel_cents': 0, 'total_cents': 750}
    # no A service was merged into B despite the similar cold 24h naming
    assert all(n['carrier'] == 'B' for n in payload['graph'] if n['service'] == 'FROZEN-24')


def test_public_quote_picks_b_at_750_for_6kg(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    published_version(db_path, 'public_tariff')
    result = quote(db_path, 'rates-1')
    assert result['chargeable_kg'] == 6.0
    totals = {(l['carrier'], l['service']): l['total_cents'] for l in result['cold_quotes']}
    assert totals == {('A', 'COLD24'): 850, ('B', 'FROZEN-24'): 750}
    # 6kg must hit the 5-10 band, never the first-page 0-5 band at 400
    a_line = next(l for l in result['cold_quotes'] if l['carrier'] == 'A')
    assert a_line['matched_band_kg'] == [5.0, 10.0]
    assert result['selected'] == {'carrier': 'B', 'service': 'FROZEN-24'} or \
           result['selected']['carrier'] == 'B'
    assert result['selected']['total_cents'] == 750
    # room temperature quoted separately
    assert [(l['carrier'], l['mode']) for l in result['room_temperature_quotes']] == [('A', 'room')]


def test_quote_without_publication_is_refused(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    build_version(db_path, 'rates-1', 'public_tariff')
    with pytest.raises(TariffError, match='no_published_version'):
        quote(db_path, 'rates-1')


# --------------------------------------------------------------------------- #
# signed addendum route
# --------------------------------------------------------------------------- #

def test_signed_addendum_merges_alias_only_after_verification(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    version_id = build_version(db_path, 'rates-1', 'signed_addendum')
    payload = graph_of(db_path, version_id)
    cold_a = node(payload['graph'], 'A', 'COLD24')
    assert cold_a['service_aliases'] == ['ICE24']
    replaced = band(cold_a, 5.0)
    # 400 base + 100 cold + 0 fuel = 500 exclusively replacing the public 5-10 band (850)
    assert replaced['pricing']['total_cents'] == 500
    assert replaced['service_alias'] == 'ICE24'
    assert replaced['source_names'] == ['signed-addendum.json']
    # untouched 0-5 public band remains
    assert band(cold_a, 0.0)['pricing']['total_cents'] == 400
    assert payload['addendum_replacements'][0]['public_band']['total_cents'] == 850
    assert payload['addendum_replacements'][0]['addendum_band']['total_cents'] == 500


def test_signed_route_quote_picks_a_at_500(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    published_version(db_path, 'signed_addendum')
    result = quote(db_path, 'rates-1')
    totals = {(l['carrier'], l['service']): l['total_cents'] for l in result['cold_quotes']}
    assert totals == {('A', 'COLD24'): 500, ('B', 'FROZEN-24'): 750}
    assert result['selected']['carrier'] == 'A'
    assert result['selected']['total_cents'] == 500


def _mutate_addendum(tmp_path, mutations, sources=None):
    names = list(sources or FROZEN)
    db_path, src_dir, contract_path, contract = seed_case(tmp_path, sources=names)
    addendum_path = src_dir / 'signed-addendum.json'
    doc = json.loads(addendum_path.read_text())
    doc.update(mutations)
    addendum_path.write_text(json.dumps(doc), encoding='utf-8')
    # re-register so the frozen case bytes capture the mutated source
    refreeze_case(db_path, 'rates-1', contract_path, src_dir)
    return db_path


def test_unsigned_addendum_blocks_signed_route_but_public_route_lives(tmp_path):
    db_path = _mutate_addendum(tmp_path, {'signature': ''})
    with pytest.raises(TariffError, match='version_validation_failed.*addendum_invalid'):
        build_version(db_path, 'rates-1', 'signed_addendum')
    # public route must still be fully buildable and publishable
    version_id = build_version(db_path, 'rates-1', 'public_tariff')
    publish(db_path, 'rates-1', 'public_tariff')
    assert quote(db_path, 'rates-1')['selected']['carrier'] == 'B'


def test_addendum_alias_on_wrong_temperature_is_rejected(tmp_path):
    db_path = _mutate_addendum(tmp_path, {'temperature': '15-25C'})
    with pytest.raises(TariffError, match='addendum_invalid'):
        build_version(db_path, 'rates-1', 'signed_addendum')


def test_addendum_outside_validity_window_is_rejected(tmp_path):
    db_path = _mutate_addendum(tmp_path, {'effective': '2026-12-02T00:00:00+08:00'})
    # extraction persists the quarantined anomaly with its concrete reason
    db = connect(db_path)
    with db:
        extraction = tariffs.extract_sources(db, 'rates-1')
    detail = db.execute(
        "SELECT detail FROM tariff_issue WHERE case_id='rates-1' AND code='addendum_invalid'"
    ).fetchone()[0]
    assert 'addendum_not_in_effect' in detail
    assert extraction['addendum_check']['reasons'] == ['addendum_not_in_effect']
    db.close()
    with pytest.raises(TariffError, match='version_validation_failed:addendum_invalid'):
        build_version(db_path, 'rates-1', 'signed_addendum')


def test_addendum_alias_to_unknown_service_is_rejected(tmp_path):
    db_path = _mutate_addendum(tmp_path, {'service_alias': {'ICE24': 'EXPRESS99'}})
    with pytest.raises(TariffError, match='addendum_band_not_found'):
        build_version(db_path, 'rates-1', 'signed_addendum')


# --------------------------------------------------------------------------- #
# pagination, revision, overlap, gap and conflict quarantine
# --------------------------------------------------------------------------- #

def test_missing_pagination_page_blocks_publication(tmp_path):
    # half-crawled set: second page exists on disk but index no longer links to it
    sources = ['carrier-a-index.html', 'carrier-a-2.html', 'carrier-b.csv', 'signed-addendum.json']
    db_path, src_dir, contract_path, contract = seed_case(tmp_path, sources=sources)
    index = (src_dir / 'carrier-a-index.html').read_text()
    (src_dir / 'carrier-a-index.html').write_text(index.replace(' data-next="carrier-a-2.html"', ''),
                                                   encoding='utf-8')
    refreeze_case(db_path, 'rates-1', contract_path, src_dir)
    with pytest.raises(TariffError, match='pagination_orphan_page'):
        build_version(db_path, 'rates-1', 'public_tariff')


def test_chain_pointing_at_unknown_page_is_blocking(tmp_path):
    sources = ['carrier-a-index.html', 'carrier-b.csv', 'signed-addendum.json']
    db_path, src_dir, contract_path, contract = seed_case(tmp_path, sources=sources)
    index = (src_dir / 'carrier-a-index.html').read_text()
    (src_dir / 'carrier-a-index.html').write_text(
        index.replace('carrier-a-2.html', 'carrier-a-missing.html'), encoding='utf-8')
    refreeze_case(db_path, 'rates-1', contract_path, src_dir)
    with pytest.raises(TariffError, match='pagination_missing_page'):
        build_version(db_path, 'rates-1', 'public_tariff')


def test_cross_page_revision_mismatch_is_quarantined(tmp_path):
    sources = ['carrier-a-index.html', 'carrier-a-2.html', 'carrier-b.csv', 'signed-addendum.json']
    db_path, src_dir, contract_path, contract = seed_case(tmp_path, sources=sources)
    page2 = (src_dir / 'carrier-a-2.html').read_text().replace('data-revision="17"',
                                                                'data-revision="18"')
    (src_dir / 'carrier-a-2.html').write_text(page2, encoding='utf-8')
    refreeze_case(db_path, 'rates-1', contract_path, src_dir)
    with pytest.raises(TariffError, match='cross_page_revision_mismatch'):
        build_version(db_path, 'rates-1', 'public_tariff')


def test_late_old_page_revision_is_quarantined(tmp_path):
    # a late-arriving old revision of page 1 re-prices the same band: conflict, no silent overwrite
    sources = ['carrier-a-index.html', 'carrier-a-2.html', 'carrier-b.csv', 'signed-addendum.json']
    db_path, src_dir, contract_path, contract = seed_case(tmp_path, sources=sources)
    old_index = (src_dir / 'carrier-a-index.html').read_text().replace('data-revision="17"',
                                                                        'data-revision="16"')
    (src_dir / 'carrier-a-index.html').write_text(old_index, encoding='utf-8')
    refreeze_case(db_path, 'rates-1', contract_path, src_dir)
    with pytest.raises(TariffError, match='cross_page_revision_mismatch'):
        build_version(db_path, 'rates-1', 'public_tariff')
    # both source bytes remain stored, nothing was overwritten
    db = connect(db_path)
    payload = json.loads(db.execute("SELECT payload FROM tariff_case WHERE id='rates-1'").fetchone()[0])
    assert len(payload['sources']) == 4
    db.close()


def test_overlapping_weight_bands_are_isolated_without_min_price_ruling(tmp_path):
    db_path, src_dir, contract_path, contract = seed_case(tmp_path)
    # widen ROOM24 to overlap itself if combined with a second conflicting row below
    html = (src_dir / 'carrier-a-index.html').read_text()
    html = html.replace('data-min-kg="0" data-max-kg="10"',
                        'data-min-kg="0" data-max-kg="12"')
    extra = ('<div data-service="ROOM24" data-temp="15-25C" data-min-kg="10" data-max-kg="20" '
             'data-base-cents="250"></div></section>')
    html = html.replace('</section>', extra)
    (src_dir / 'carrier-a-index.html').write_text(html, encoding='utf-8')
    refreeze_case(db_path, 'rates-1', contract_path, src_dir)
    with pytest.raises(TariffError, match='overlapping_weight_band'):
        build_version(db_path, 'rates-1', 'public_tariff')


def test_weight_band_gap_is_blocking(tmp_path):
    sources = ['carrier-a-index.html', 'carrier-a-2.html', 'carrier-b.csv', 'signed-addendum.json']
    db_path, src_dir, contract_path, contract = seed_case(tmp_path, sources=sources)
    page2 = (src_dir / 'carrier-a-2.html').read_text().replace('data-min-kg="5"', 'data-min-kg="6"')
    (src_dir / 'carrier-a-2.html').write_text(page2, encoding='utf-8')
    refreeze_case(db_path, 'rates-1', contract_path, src_dir)
    with pytest.raises(TariffError, match='weight_band_gap'):
        build_version(db_path, 'rates-1', 'public_tariff')


def test_cross_page_conflicting_price_keeps_both_sources(tmp_path):
    sources = ['carrier-a-index.html', 'carrier-a-2.html', 'carrier-b.csv', 'signed-addendum.json']
    db_path, src_dir, contract_path, contract = seed_case(tmp_path, sources=sources)
    # page 2 repeats the 0-5 COLD24 band with a different price -> conflict, no last-row override
    page2 = (src_dir / 'carrier-a-2.html').read_text()
    conflict = ('<div data-service="COLD24" data-temp="2-8C" data-min-kg="0" data-max-kg="5" '
                'data-base-cents="999"></div></section>')
    (src_dir / 'carrier-a-2.html').write_text(page2.replace('</section>', conflict), encoding='utf-8')
    refreeze_case(db_path, 'rates-1', contract_path, src_dir)
    with pytest.raises(TariffError, match='cross_page_conflict_price'):
        build_version(db_path, 'rates-1', 'public_tariff')


def test_duplicate_identical_revision_is_deduped_with_info_issue(tmp_path):
    db_path, src_dir, contract_path, contract = seed_case(tmp_path)
    html = (src_dir / 'carrier-a-index.html').read_text()
    # repeat the exact same ROOM24 row once more
    html = html.replace('</section>',
                        '<div data-service="ROOM24" data-temp="15-25C" data-min-kg="0" '
                        'data-max-kg="10" data-base-cents="300"></div></section>')
    (src_dir / 'carrier-a-index.html').write_text(html, encoding='utf-8')
    refreeze_case(db_path, 'rates-1', contract_path, src_dir)
    version_id = build_version(db_path, 'rates-1', 'public_tariff')
    payload = graph_of(db_path, version_id)
    room = node(payload['graph'], 'A', 'ROOM24')
    assert len(room['bands']) == 1
    assert any(i['code'] == 'duplicate_revision' and not i['blocking'] for i in payload['issues'])


# --------------------------------------------------------------------------- #
# publication fence: partial push, ACK loss, concurrency, old-version stability
# --------------------------------------------------------------------------- #

def test_partial_service_push_is_rejected_and_old_version_stays(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    published_version(db_path, 'public_tariff')
    first_quote = quote(db_path, 'rates-1')
    # now build the signed route but the endpoint only accepts part of the services
    build_version(db_path, 'rates-1', 'signed_addendum')
    with pytest.raises(TariffError, match='publish_rejected:partial_service_set'):
        publish(db_path, 'rates-1', 'signed_addendum', MockRateMaster(partial_services=True))
    db = connect(db_path)
    acked = db.execute("SELECT count(*) FROM tariff_publication WHERE acked=1").fetchone()[0]
    assert acked == 1
    db.close()
    # old current version remains queryable; no half-version billing
    assert quote(db_path, 'rates-1')['version_id'] == first_quote['version_id']
    assert quote(db_path, 'rates-1')['selected']['total_cents'] == 750


def test_lost_ack_retry_is_idempotent(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    version_id = build_version(db_path, 'rates-1', 'public_tariff')
    endpoint = MockRateMaster(lose_ack=True)
    with pytest.raises(TariffError, match='publish_rejected:ack_lost'):
        publish(db_path, 'rates-1', 'public_tariff', endpoint)
    # no current publication while the ACK was lost
    db = connect(db_path)
    assert db.execute("SELECT count(*) FROM tariff_publication WHERE acked=1").fetchone()[0] == 0
    db.close()
    endpoint.lose_ack = False
    receipt = publish(db_path, 'rates-1', 'public_tariff', endpoint)
    assert receipt['version_id'] == version_id
    # retrying again returns the same receipt and does not create a second current row
    again = publish(db_path, 'rates-1', 'public_tariff', endpoint)
    assert again['receipt'] == receipt['receipt'] and again['idempotent']
    db = connect(db_path)
    assert db.execute("SELECT count(*) FROM tariff_publication WHERE acked=1").fetchone()[0] == 1
    db.close()


def test_concurrent_publishers_only_one_acked_current(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    build_version(db_path, 'rates-1', 'public_tariff')
    build_version(db_path, 'rates-1', 'signed_addendum')
    # two workers hold BEGIN IMMEDIATE on the same SQLite file at once
    first = connect(db_path)
    first.execute('BEGIN IMMEDIATE')
    second = connect(db_path)
    with pytest.raises(sqlite3.OperationalError):
        second.execute('BEGIN IMMEDIATE')
    second.close()
    first.rollback()
    first.close()
    # after the lock clears, publication succeeds normally
    publish(db_path, 'rates-1', 'public_tariff')
    db = connect(db_path)
    assert db.execute("SELECT count(*) FROM tariff_publication WHERE acked=1").fetchone()[0] == 1
    db.close()


def test_publish_while_another_worker_holds_write_lock_is_refused(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    build_version(db_path, 'rates-1', 'public_tariff')
    holder = connect(db_path)
    holder.execute('BEGIN IMMEDIATE')
    try:
        with pytest.raises(TariffError, match='publish_concurrent'):
            publish(db_path, 'rates-1', 'public_tariff')
    finally:
        holder.rollback()
        holder.close()
    db = connect(db_path)
    assert db.execute("SELECT count(*) FROM tariff_publication").fetchone()[0] == 0
    db.close()


def test_nack_rows_are_kept_but_never_become_current(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    build_version(db_path, 'rates-1', 'public_tariff')
    with pytest.raises(TariffError, match='publish_rejected:ack_lost'):
        publish(db_path, 'rates-1', 'public_tariff', MockRateMaster(lose_ack=True))
    db = connect(db_path)
    nack = db.execute("SELECT receipt,acked,superseded FROM tariff_publication").fetchone()
    assert nack['acked'] == 0 and nack['superseded'] == 0
    assert json.loads(nack['receipt'])['reason'] == 'ack_lost'
    assert db.execute(
        "SELECT count(*) FROM tariff_publication WHERE acked=1 AND superseded=0").fetchone()[0] == 0
    db.close()


def test_single_page_alone_cannot_go_live(tmp_path):
    # only the first A page, honestly declared: no 5-10kg band, the 6kg box has no covered price
    sources = ['carrier-a-index.html']
    db_path, src_dir, contract_path, contract = seed_case(tmp_path, sources=sources)
    # the lone page cannot point at a page outside the frozen set: drop the link
    index = (src_dir / 'carrier-a-index.html').read_text().replace(
        ' data-next="carrier-a-2.html"', '')
    (src_dir / 'carrier-a-index.html').write_text(index, encoding='utf-8')
    refreeze_case(db_path, 'rates-1', contract_path, src_dir)
    with pytest.raises(TariffError, match='version_box_weight_uncovered'):
        build_version(db_path, 'rates-1', 'public_tariff')


def test_half_crawled_second_page_is_quarantined(tmp_path):
    # both pages frozen but page 2 lost its revision marker: an unparseable/half page must block
    db_path, src_dir, contract_path, contract = seed_case(tmp_path)
    page2 = (src_dir / 'carrier-a-2.html').read_text().replace('data-revision="17"', '')
    (src_dir / 'carrier-a-2.html').write_text(page2, encoding='utf-8')
    refreeze_case(db_path, 'rates-1', contract_path, src_dir)
    with pytest.raises(TariffError):
        build_version(db_path, 'rates-1', 'public_tariff')


def test_unauthorized_authority_is_refused(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    db = connect(db_path)
    payload = json.loads(db.execute("SELECT payload FROM tariff_case WHERE id='rates-1'").fetchone()[0])
    payload['contract']['allowed_authorities'] = ['public_tariff']
    db.execute('UPDATE tariff_case SET payload=? WHERE id=?',
               (json.dumps(payload, sort_keys=True, separators=(",", ":")), 'rates-1'))
    db.commit()
    db.close()
    with pytest.raises(TariffError, match='authority_not_authorized'):
        build_version(db_path, 'rates-1', 'signed_addendum')


# --------------------------------------------------------------------------- #
# corrections: new versions, diff audit, immutable quote history
# --------------------------------------------------------------------------- #

def test_correction_uses_new_version_and_keeps_old_quote_history(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    v_public, _ = published_version(db_path, 'public_tariff')
    old_quote = quote(db_path, 'rates-1')
    assert old_quote['selected']['total_cents'] == 750
    v_signed, receipt = published_version(db_path, 'signed_addendum')
    assert v_public != v_signed
    assert receipt['superseded'] == v_public
    new_quote = quote(db_path, 'rates-1')
    assert new_quote['version_id'] == v_signed
    assert new_quote['selected']['total_cents'] == 500
    # historical quote row still references the old ACKed version and its old price
    history = tariffs.list_quotes(db_path, 'rates-1')
    assert [q['version_id'] for q in history] == [v_public, v_signed]
    assert history[0]['selected']['total_cents'] == 750
    audits = tariffs.audit_trail(db_path, 'rates-1')
    assert len(audits) == 1
    change = next(c for c in audits[0]['changes']
                  if c['service'] == 'COLD24' and c['band_kg'] == [5.0, 10.0])
    assert change['total_cents_before'] == 850
    assert change['total_cents_after'] == 500
    assert change['delta_cents'] == -350


def test_quotes_never_read_web_pages_directly(tmp_path):
    db_path, src_dir, _, _ = seed_case(tmp_path)
    published_version(db_path, 'public_tariff')
    result_before = quote(db_path, 'rates-1')
    # mutate every source file on disk after publication; quotes must be unchanged
    for path in src_dir.iterdir():
        path.write_text('tampered after publication', encoding='utf-8')
    result_after = quote(db_path, 'rates-1')
    assert result_after == result_before
    assert result_after['version_id']


def test_scale_limits_enforced(tmp_path):
    db_path, src_dir, contract_path, contract = seed_case(tmp_path)
    # 101 distinct bands across the carrier pages
    rows = ''.join(
        f'<div data-service="ROOM24" data-temp="15-25C" data-min-kg="{i}" data-max-kg="{i + 1}" '
        f'data-base-cents="10"></div>' for i in range(101))
    (src_dir / 'carrier-a-index.html').write_text(
        '<html><body><section data-carrier="A" data-revision="17">' + rows +
        '</section></body></html>', encoding='utf-8')
    refreeze_case(db_path, 'rates-1', contract_path, src_dir)
    with pytest.raises(TariffError, match='band_limit_exceeded'):
        build_version(db_path, 'rates-1', 'public_tariff')


# --------------------------------------------------------------------------- #
# reports and CLI
# --------------------------------------------------------------------------- #

def test_reports_include_json_and_markdown_graph_diff_quotes(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    published_version(db_path, 'public_tariff')
    quote(db_path, 'rates-1')
    published_version(db_path, 'signed_addendum')
    quote(db_path, 'rates-1')
    out = tmp_path / 'reports'
    paths = write_reports(db_path, 'rates-1', out)
    for name in ('rate-map.json', 'rate-map.md', 'rate-diff.json', 'rate-diff.md',
                 'quotes.json', 'quotes.md'):
        assert (out / name).exists()
    md = (out / 'rate-map.md').read_text(encoding='utf-8')
    assert 'COLD24' in md and '850' in md and 'FROZEN-24' in md
    diff = json.loads((out / 'rate-diff.json').read_text(encoding='utf-8'))
    assert any(c['delta_cents'] == -350 for a in diff['audits'] for c in a['changes'])
    quote_md = (out / 'quotes.md').read_text(encoding='utf-8')
    assert '计费重量 6kg' in quote_md and '室温' in quote_md


def test_cli_end_to_end(tmp_path):
    import subprocess
    import sys
    db_path = tmp_path / 'cli.db'
    source_dir = tmp_path / 'src'
    source_dir.mkdir()
    for name in FROZEN:
        shutil.copy(FIX / name, source_dir / name)
    contract = tmp_path / 'contract.json'
    contract.write_text((FIX / 'tariff-contract.json').read_text(), encoding='utf-8')
    init(db_path, 'batch-t', 'box-A')
    ingest(FIX / 'tariff-events.jsonl', db_path)
    base = [sys.executable, '-I', '-m', 'coldhandoff']
    run = lambda *args: subprocess.run(base + list(args), cwd=Path(__file__).resolve().parents[1],
                                       check=True, capture_output=True, text=True)
    run('tariff-register', '--db', str(db_path), '--case', 'rates-1',
        '--contract', str(contract), '--source-dir', str(source_dir))
    run('tariff-build', '--db', str(db_path), '--case', 'rates-1',
        '--authority', 'public_tariff')
    run('tariff-publish', '--db', str(db_path), '--case', 'rates-1',
        '--authority', 'public_tariff')
    out = run('tariff-quote', '--db', str(db_path), '--case', 'rates-1')
    payload = json.loads(out.stdout)
    assert payload['selected']['total_cents'] == 750
    report_out = tmp_path / 'rep'
    run('tariff-report', '--db', str(db_path), '--case', 'rates-1', '--out', str(report_out))
    assert (report_out / 'rate-map.json').exists()


def test_original_scan_and_source_bytes_remain_untouched(tmp_path):
    db_path, _, _, _ = seed_case(tmp_path)
    published_version(db_path, 'public_tariff')
    quote(db_path, 'rates-1')
    db = connect(db_path)
    # original arrival event still present and temperature decision machinery is not read
    assert db.execute("SELECT count(*) FROM raw_event WHERE kind='arrival'").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM decision").fetchone()[0] == 0
    case = json.loads(db.execute("SELECT payload FROM tariff_case WHERE id='rates-1'").fetchone()[0])
    import hashlib
    assert all(hashlib.sha256(s['body'].encode()).hexdigest() == s['sha256']
               for s in case['sources'])
    db.close()
