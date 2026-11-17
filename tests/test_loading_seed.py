from pathlib import Path
from coldhandoff.__main__ import init
from coldhandoff.ingest import ingest
from coldhandoff.loading import register
from coldhandoff.rules import evaluate
from coldhandoff.store import connect
import pytest

FIXTURES=Path(__file__).resolve().parents[1]/'fixtures'

def ready(tmp_path):
    db=tmp_path/'loading.db'
    for box in 'ABCD':init(db,'batch-loading',box)
    assert ingest(FIXTURES/'loading-events.jsonl',db)['imported']==24
    assert evaluate(db)=={box:'完整' for box in 'ABCD'}
    return db

def test_freezes_eligible_boxes_without_load_solution(tmp_path):
    db=ready(tmp_path);got=register(db,'load-01',FIXTURES/'loading-tender.json')
    assert got['eligible_boxes']==4
    assert register(db,'load-01',FIXTURES/'loading-tender.json')==got
    con=connect(db)
    try:assert con.execute('SELECT COUNT(*) FROM loading_case').fetchone()[0]==1
    finally:con.close()

def test_missing_box_decision_rejected(tmp_path):
    db=tmp_path/'empty.db'
    with pytest.raises(ValueError,match='box_not_loading_eligible'):register(db,'load-01',FIXTURES/'loading-tender.json')
