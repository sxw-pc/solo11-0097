from pathlib import Path
from coldhandoff.__main__ import init
from coldhandoff.ingest import ingest
from coldhandoff.rules import evaluate
from coldhandoff.store import connect
from coldhandoff.thermal import register
import pytest

FIXTURES=Path(__file__).resolve().parents[1]/'fixtures'

def test_ambient_case_freezes_existing_points_without_core_solution(tmp_path):
    db=tmp_path/'thermal.db';init(db,'batch-thermal','box-thermal')
    assert ingest(FIXTURES/'thermal-events.jsonl',db)['imported']==8
    assert evaluate(db)['box-thermal']=='完整'
    got=register(db,'core-01',FIXTURES/'thermal-case.json')
    assert got['sample_count']==4
    assert register(db,'core-01',FIXTURES/'thermal-case.json')==got
    con=connect(db)
    try:assert con.execute('SELECT COUNT(*) FROM thermal_case').fetchone()[0]==1
    finally:con.close()

def test_missing_ambient_points_cannot_register(tmp_path):
    db=tmp_path/'thermal.db';init(db,'batch-thermal','box-thermal')
    with pytest.raises(ValueError,match='thermal_sample_gap'):register(db,'core-01',FIXTURES/'thermal-case.json')
