"""The packaged label demo must stay runnable and produce a complete audit set."""
import json
from pathlib import Path

from coldhandoff.label_demo import label_demo
from coldhandoff.store import connect


def test_label_demo_produces_usable_labels_and_full_audit(tmp_path):
    out = label_demo(tmp_path)
    data = json.loads(out.read_text(encoding='utf-8'))
    # Exactly one current valid label per real business box.
    usable = {r['box_id']: r for r in data['current_usable']}
    assert set(usable) == {'A', 'B'}
    assert usable['A']['serial'] == 'SER-0003'  # reprint after the drill
    assert usable['B']['serial'] == 'SER-0002'
    # The jammed-then-voided serial is revoked with destruction evidence.
    serials = {r['serial']: r for r in data['serials']}
    assert serials['SER-0001']['state'] == 'revoked'
    assert any(c['serial'] == 'SER-0003' and c['replaces'] == 'SER-0001'
               for c in data['replacement_chains'])
    # Device journals remain hash-chain intact.
    assert all(j['chain_ok'] for j in data['device_journals'].values())
    # Physical paper exists for every emitted serial.
    assert all(p['paper_exists'] for p in data['physical_paper'])
    # The unexecuted control layout never reached the printer.
    control = json.loads((tmp_path / 'label-demo-summary.json').read_text(
        encoding='utf-8'))['unexecuted_control_layout']
    assert control['rendered_but_not_printed']
    assert not (tmp_path / 'devices' / 'PRN-1' / 'paper'
                / 'SER-CONTROL-NOT-ISSUED.lbl').exists()
    assert Path(control['path']).read_bytes()  # rendered control bytes exist
    # Markdown report is generated alongside the JSON one.
    assert out.with_suffix('.md').read_text(encoding='utf-8').startswith(
        '# 实体标签制发审计报告')


def test_label_demo_never_touches_temperature_decisions(tmp_path):
    label_demo(tmp_path)
    con = connect(tmp_path / 'coldhandoff.db')
    assert con.execute('SELECT count(*) FROM decision').fetchone()[0] == 0
    con.close()
