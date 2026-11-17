from pathlib import Path
from coldhandoff.__main__ import init
from coldhandoff.ingest import ingest
from coldhandoff.rules import evaluate
from coldhandoff.privacy_export import register
from coldhandoff.store import connect


def test_export_case_has_identifiable_denormalized_source(tmp_path):
    db=tmp_path/'cold.db'
    init(db,'batch-1','A')
    fixtures=Path(__file__).parents[1]/'fixtures'
    ingest(fixtures/'privacy-events.jsonl',db)
    evaluate(db)
    assert register(db,fixtures/'export-contract.json')=='evidence-export-2030-06-08'
    con=connect(db)
    assert b'MIRA-PRIVATE' in con.execute('SELECT raw FROM source_file').fetchone()[0]
    assert 'MIRA-PRIVATE' in con.execute('SELECT payload FROM raw_event WHERE kind="sign"').fetchone()[0]
    assert con.execute('SELECT source_digest FROM export_case').fetchone()[0]
    con.close()
