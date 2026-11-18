import hashlib
import json
from pathlib import Path
import pytest
from coldhandoff.__main__ import init
from coldhandoff.ingest import ingest
from coldhandoff.tariffs import register
from coldhandoff.store import connect


FIX = Path(__file__).resolve().parents[1] / 'fixtures'


def test_tariff_seed_freezes_actual_box_and_all_source_bytes(tmp_path):
    db_path = tmp_path / 'tariff.db'
    init(db_path, 'batch-t', 'box-A')
    assert ingest(FIX / 'tariff-events.jsonl', db_path)['imported'] == 1
    assert register(db_path, 'rates-1', FIX / 'tariff-contract.json', FIX) == {'case_id': 'rates-1', 'sources': 4}
    db = connect(db_path)
    payload = json.loads(db.execute('SELECT payload FROM tariff_case').fetchone()[0])
    # 只核对真实到仓来源与四份冻结文件的原字节/SHA，不含任何费率结果
    assert payload['box']['id'] == 'box-A'
    assert payload['arrival']['source_sha']
    frozen_names = json.loads((FIX / 'tariff-contract.json').read_text())['source_pages']
    assert frozen_names == ['carrier-a-index.html', 'carrier-a-2.html', 'carrier-b.csv',
                            'signed-addendum.json']
    assert [s['name'] for s in payload['sources']] == frozen_names
    assert all(hashlib.sha256(s['body'].encode()).hexdigest() == s['sha256'] for s in payload['sources'])
    # 原始箱扫描与来源字节仍然保留
    assert db.execute("SELECT count(*) FROM raw_event WHERE box_id='box-A' AND kind='arrival'").fetchone()[0] == 1
    db.close()


def test_tariff_seed_requires_real_arrival(tmp_path):
    db_path = tmp_path / 'tariff.db'
    init(db_path, 'batch-t', 'box-A')
    with pytest.raises(ValueError, match='tariff_box_arrival_missing'):
        register(db_path, 'rates-1', FIX / 'tariff-contract.json', FIX)
