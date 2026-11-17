from pathlib import Path

import pytest

from coldhandoff.__main__ import init
from coldhandoff.hold_control import actuate, cooler_state, observe, register, state
from coldhandoff.ingest import ingest
from coldhandoff.rules import evaluate


FIX = Path(__file__).resolve().parent.parent / 'fixtures'


def prepared(tmp_path, name):
    db = tmp_path / name
    init(db, 'batch-1', 'box-A')
    init(db, 'batch-1', 'box-B')
    assert ingest(FIX / 'hold_events.jsonl', db)['imported'] == 14
    assert evaluate(db) == {'box-A': '完整', 'box-B': '完整'}
    assert register(db, 'hold-1', FIX / 'hold_case.json')['boxes'] == 2
    return db


def run_plan(db, steps):
    out = [actuate(db, 'hold-1', i, box, f'step-{i}') for i, box in enumerate(steps)]
    return (sum(x['energy_cents'] for x in out),
            {box: sum(x['boxes'][box]['exposure'] for x in out) for box in ('box-A', 'box-B')},
            [x['cooled_box'] for x in out])


def test_distinct_physical_control_results(tmp_path):
    cheap = prepared(tmp_path, 'cheap.db')
    assert run_plan(cheap, ['box-B', None, 'box-A']) == (
        600, {'box-A': 3, 'box-B': 2}, ['box-B', None, 'box-A'])
    assert [x['temperature'] for x in state(cheap, 'hold-1')] == [7, 7]
    assert cooler_state(cheap, 'hold-1') == 0
    assert actuate(cheap, 'hold-1', 0, 'box-B', 'step-0')['status'] == 'replayed'

    balanced = prepared(tmp_path, 'balanced.db')
    assert run_plan(balanced, ['box-B', 'box-A', None]) == (
        1100, {'box-A': 1, 'box-B': 2}, ['box-B', 'box-A', None])
    assert [x['temperature'] for x in state(balanced, 'hold-1')] == [7, 7]
    assert cooler_state(balanced, 'hold-1') == 0


def test_observation_updates_future_state_without_rewriting_action(tmp_path):
    db = prepared(tmp_path, 'feedback.db')
    first = actuate(db, 'hold-1', 0, 'box-A', 'first')
    assert first['boxes']['box-B']['temperature'] == 6
    obs = observe(db, 'hold-1', FIX / 'hold_feedback.json')
    assert obs['actual_temperature'] == 8 and obs['predicted_temperature'] == 6
    assert cooler_state(db, 'hold-1') == 1
    assert actuate(db, 'hold-1', 0, 'box-A', 'first')['status'] == 'replayed'
    assert state(db, 'hold-1')[1]['temperature'] == 8
    assert observe(db, 'hold-1', FIX / 'hold_feedback.json')['status'] == 'replayed'


def test_period_and_source_guards(tmp_path):
    db = prepared(tmp_path, 'guard.db')
    with pytest.raises(ValueError, match='period_sequence_conflict'):
        actuate(db, 'hold-1', 1, None, 'early')
    with pytest.raises(ValueError, match='hold_period_not_executed'):
        observe(db, 'hold-1', FIX / 'hold_feedback.json')
    assert cooler_state(db, 'hold-1') == 2


def test_requires_original_complete_handoff(tmp_path):
    db = tmp_path / 'missing.db'
    init(db, 'batch-1', 'box-A')
    init(db, 'batch-1', 'box-B')
    with pytest.raises(ValueError, match='box_not_handoff_complete'):
        register(db, 'hold-1', FIX / 'hold_case.json')
