"""End-to-end audit anchoring: registry, checkpoints, witnesses, recovery."""

import json
import sqlite3
from pathlib import Path

import pytest

from coldhandoff.__main__ import init
from coldhandoff import audit_anchor as A
from coldhandoff.ingest import ingest
from coldhandoff.merkle import DomainTags, mth, verify_inclusion, verify_consistency

FIXTURES = Path(__file__).parents[1] / "fixtures"
CONTRACT = FIXTURES / "anchor-contract.json"


def make_db(tmp_path, boxes=("A", "B")):
    db = tmp_path / "cold.db"
    for box in boxes:
        init(db, "batch-1", box)
    return db


def seed(tmp_path, boxes=("A", "B")):
    """Two real ingested sources, registered as the frozen anchor case."""

    db = make_db(tmp_path, boxes)
    ingest(FIXTURES / "source-one.jsonl", db)
    ingest(FIXTURES / "source-two.jsonl", db)
    assert A.register(db, CONTRACT) == "source-anchor-2030-06-09"
    return db


def seed_appended(tmp_path):
    db = seed(tmp_path)
    A.append_from_ingest(db, CONTRACT)
    return db


def write_source(tmp_path, name, device, box, stamp):
    path = tmp_path / name
    path.write_text(
        json.dumps(
            {
                "kind": "dispatch",
                "device": device,
                "seq": 1,
                "box_id": box,
                "event_time": stamp,
            }
        ),
        encoding="utf-8",
    )
    return path


def add_third_source(tmp_path, db, stamp="2030-06-09T08:02:00Z"):
    init(db, "batch-1", "C")
    ingest(write_source(tmp_path, "source-three.jsonl", "dev-C", "C", stamp), db)
    return A.append_from_ingest(db, CONTRACT)


def checkpoint_rows(db):
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute("SELECT * FROM anchor_checkpoint ORDER BY number")]
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Seed identity and registry
# ---------------------------------------------------------------------------


def test_register_keeps_original_contract(tmp_path):
    db = seed(tmp_path)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    case = dict(con.execute("SELECT * FROM anchor_case").fetchone())
    snapshot = json.loads(case["source_snapshot"])
    assert [row["id"] for row in snapshot] == [1, 2]
    assert all(len(row["hash"]) == 64 for row in snapshot)
    assert case["source_snapshot"] == json.dumps(snapshot, sort_keys=True)
    assert con.execute("SELECT count(*) FROM decision").fetchone()[0] == 0
    con.close()


def test_leaves_bind_ingested_source_identity_bytes_and_version(tmp_path):
    db = seed_appended(tmp_path)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute("SELECT * FROM anchor_leaf ORDER BY leaf_index")]
    sources = [dict(r) for r in con.execute("SELECT id,hash FROM source_file ORDER BY id")]
    con.close()
    assert len(rows) == 2
    assert [r["leaf_index"] for r in rows] == [0, 1]
    for row, source in zip(rows, sources):
        payload = json.loads(row["payload_json"])
        assert payload["bytes_sha256"] == source["hash"]
        assert payload["import_version"] == "1"
        assert row["source_id"] == A.durable_source_id("source-anchor-2030-06-09", source["id"])
    assert rows[0]["source_id"] != rows[1]["source_id"]


def test_duplicate_bytes_with_different_source_ids_get_distinct_leaves(tmp_path):
    db = seed_appended(tmp_path)
    payload_bytes = (FIXTURES / "source-one.jsonl").read_bytes()
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    first_hash = dict(con.execute("SELECT * FROM anchor_leaf WHERE leaf_index=0").fetchone())["leaf_hash"]
    con.close()
    # Re-ingesting identical bytes is an ingest-level duplicate and must not
    # create a second source_file row.
    assert ingest(FIXTURES / "source-one.jsonl", db)["duplicate_file"]
    # But two independent source identities over the same bytes are two leaves.
    A.append_sources(
        db,
        CONTRACT,
        [
            {"source_id": "mirror-a", "bytes_sha256": first_hash and __import__("hashlib").sha256(payload_bytes).hexdigest()},
            {"source_id": "mirror-b", "bytes_sha256": __import__("hashlib").sha256(payload_bytes).hexdigest()},
        ],
    )
    summary = A.publish_checkpoint(db, CONTRACT)
    mirrors = [leaf for leaf in summary["leaves"] if leaf["source_id"].startswith("mirror-")]
    assert len(mirrors) == 2
    assert mirrors[0]["leaf_hash"] != mirrors[1]["leaf_hash"]


def test_reappending_the_same_source_id_is_rejected(tmp_path):
    db = seed_appended(tmp_path)
    A.append_source(db, CONTRACT, "stable-id", "aa" * 32)
    with pytest.raises(A.AnchorError):
        A.append_source(db, CONTRACT, "stable-id", "bb" * 32)
    con = sqlite3.connect(db)
    assert con.execute("SELECT count(*) FROM anchor_leaf WHERE source_id='stable-id'").fetchone()[0] == 1
    con.close()


def test_append_requires_registered_case_and_valid_leaf(tmp_path):
    db = make_db(tmp_path)
    ingest(FIXTURES / "source-one.jsonl", db)
    ingest(FIXTURES / "source-two.jsonl", db)
    with pytest.raises(A.AnchorError):
        A.append_source(db, CONTRACT, "x", "aa" * 32)
    A.register(db, CONTRACT)
    with pytest.raises(A.AnchorError):
        A.append_source(db, CONTRACT, "", "aa" * 32)
    with pytest.raises(A.AnchorError):
        A.append_source(db, CONTRACT, "x", "not-hex")
    with pytest.raises(A.AnchorError):
        A.append_correction(db, CONTRACT, "r1", "missing", kind="revoke")


# ---------------------------------------------------------------------------
# Checkpoints, inclusion and consistency
# ---------------------------------------------------------------------------


def test_checkpoint_is_stable_and_never_renumbered(tmp_path):
    db = seed_appended(tmp_path)
    first = A.publish_checkpoint(db, CONTRACT)
    again = A.publish_checkpoint(db, CONTRACT)
    assert first["checkpoint_number"] == again["checkpoint_number"] == 1
    assert first["root"] == again["root"]
    assert len(checkpoint_rows(db)) == 1


def test_non_power_of_two_sizes_have_valid_inclusion_paths(tmp_path):
    db = seed_appended(tmp_path)
    for i in range(5):
        A.append_source(db, CONTRACT, f"extra-{i}", f"{i:064x}")
    summary = A.publish_checkpoint(db, CONTRACT)
    assert summary["tree_size"] == 7
    bundle = A.audit_bundle(db, CONTRACT, summary["checkpoint_number"])
    assert A.verify_bundle(bundle)["ok"] is True
    assert len(bundle["inclusions"]) == 7
    for source_id, doc in bundle["inclusions"].items():
        assert doc["tree_size"] == 7
        assert doc["root"] == summary["root"]


def test_inclusion_works_for_single_leaf_tree(tmp_path):
    db = seed(tmp_path)
    A.append_source(db, CONTRACT, "only-source", "aa" * 32)
    summary = A.publish_checkpoint(db, CONTRACT)
    assert summary["tree_size"] == 1
    bundle = A.audit_bundle(db, CONTRACT, summary["checkpoint_number"])
    assert bundle["inclusions"]["only-source"]["path"] == []
    assert A.verify_bundle(bundle)["ok"] is True


def test_empty_tree_checkpoint_has_empty_root(tmp_path):
    db = seed(tmp_path)
    summary = A.publish_checkpoint(db, CONTRACT)
    assert summary["tree_size"] == 0
    assert summary["root"] == DomainTags().empty_root.hex()
    bundle = A.audit_bundle(db, CONTRACT, summary["checkpoint_number"])
    assert bundle["leaves"] == []
    assert A.verify_bundle(bundle)["ok"] is True
    # An empty checkpoint is a legal ancestor of any later tree.
    A.append_source(db, CONTRACT, "late-source", "bb" * 32)
    newer = A.publish_checkpoint(db, CONTRACT)
    proof = A.consistency_between(db, CONTRACT, summary["checkpoint_number"], newer["checkpoint_number"])
    assert proof["proof"] == []
    assert proof["verified"] is True


def test_consistency_between_checkpoints_is_independently_verifiable(tmp_path):
    db = seed_appended(tmp_path)
    old = A.publish_checkpoint(db, CONTRACT)
    add_third_source(tmp_path, db)
    new = A.publish_checkpoint(db, CONTRACT)
    doc = A.consistency_between(db, CONTRACT, old["checkpoint_number"], new["checkpoint_number"])
    assert doc["verified"] is True
    # A verifier with only the roots, sizes and proof can reproduce it.
    assert verify_consistency(
        doc["old_tree_size"], doc["new_tree_size"], doc["old_root"], doc["new_root"], doc["proof"]
    )
    broken = dict(doc)
    broken["proof"] = doc["proof"][:-1]
    assert A.verify_consistency_document(broken) is False


def test_deleted_first_source_fails_old_to_new_consistency(tmp_path):
    """Deleting the first source and re-rooting is self-consistent, but the
    previously delivered old root no longer verifies as a prefix."""

    db = seed_appended(tmp_path)
    old = A.publish_checkpoint(db, CONTRACT)
    delivered = A.audit_bundle(
        db, CONTRACT, old["checkpoint_number"], consistency_from=None
    )
    add_third_source(tmp_path, db)
    rewritten = A.publish_checkpoint(db, CONTRACT)

    case = json.loads(CONTRACT.read_text())["case_id"]
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    leaves = [dict(r) for r in con.execute("SELECT * FROM anchor_leaf WHERE case_id=? ORDER BY leaf_index", (case,))]
    con.execute("DELETE FROM anchor_leaf WHERE case_id=?", (case,))
    con.execute("INSERT INTO anchor_leaf VALUES (?,?,?,?,?,?,?,?)", (
        case, 0, leaves[1]["source_id"], leaves[1]["kind"],
        leaves[1]["payload_json"], leaves[1]["leaf_hash"],
        leaves[1]["import_version"], leaves[1]["created_at"],
    ))
    con.commit()
    forked_root = mth([bytes.fromhex(leaves[1]["leaf_hash"])]).hex()
    con.execute("UPDATE anchor_checkpoint SET tree_size=1,root=? WHERE case_id=? AND number=?",
                (forked_root, case, rewritten["checkpoint_number"]))
    con.commit()
    con.close()

    assert verify_consistency(2, 1, old["root"], forked_root, []) is False
    assert verify_consistency(2, 2, old["root"], forked_root, []) is False
    # The committed leaves no longer reproduce the published root.  A new
    # checkpoint at the same size is refused rather than silently reissued.
    assert A.publish_checkpoint(db, CONTRACT)["root"] == forked_root
    with pytest.raises(A.AnchorError):
        A.consistency_between(db, CONTRACT, old["checkpoint_number"], rewritten["checkpoint_number"])
    # The package delivered yesterday still verifies against its own root.
    assert A.verify_bundle(delivered)["ok"] is True


def test_consistency_rejects_old_checkpoint_after_new(tmp_path):
    db = seed_appended(tmp_path)
    A.publish_checkpoint(db, CONTRACT)
    add_third_source(tmp_path, db)
    A.publish_checkpoint(db, CONTRACT)
    with pytest.raises(A.AnchorError):
        A.consistency_between(db, CONTRACT, 2, 1)


# ---------------------------------------------------------------------------
# Deliveries and witness protocol
# ---------------------------------------------------------------------------


def test_local_signed_delivery_is_immediate(tmp_path):
    db = seed_appended(tmp_path)
    summary = A.publish_checkpoint(db, CONTRACT)
    delivery = A.build_delivery(db, CONTRACT, summary["checkpoint_number"], "local_signed")
    assert delivery["status"] == "complete"
    assert delivery["root"] == summary["root"]
    assert set(delivery["inclusions"]) == {leaf["source_id"] for leaf in summary["leaves"]}
    assert delivery["local_signature"]["signature"]


def test_dual_witness_requires_both_receipts_on_the_same_root(tmp_path):
    db = seed_appended(tmp_path)
    summary = A.publish_checkpoint(db, CONTRACT, policy="dual_witness")
    number = summary["checkpoint_number"]
    assert A.build_delivery(db, CONTRACT, number, "dual_witness")["status"] == "pending_verification"
    A.simulate_witness_ack(db, CONTRACT, number, "W1")
    assert A.build_delivery(db, CONTRACT, number, "dual_witness")["status"] == "pending_verification"
    A.simulate_witness_ack(db, CONTRACT, number, "W2")
    delivery = A.build_delivery(db, CONTRACT, number, "dual_witness")
    assert delivery["status"] == "complete"
    assert {r["witness_id"] for r in delivery["receipts"]} == {"W1", "W2"}
    assert all(r["root"] == summary["root"] for r in delivery["receipts"])
    assert all(r["snapshot_sha256"] == summary["snapshot_sha256"] for r in delivery["receipts"])


def test_both_evidence_packages_share_bytes_but_differ_in_trust(tmp_path):
    """local_signed and dual_witness cite the same source bytes but have
    different trust issuers, credentials and issue times."""

    db = seed_appended(tmp_path)
    summary = A.publish_checkpoint(db, CONTRACT)
    number = summary["checkpoint_number"]
    A.simulate_witness_ack(db, CONTRACT, number, "W1", signed_at="2030-06-09T10:00:00+00:00")
    A.simulate_witness_ack(db, CONTRACT, number, "W2", signed_at="2030-06-09T10:05:00+00:00")
    keyring = A.export_keyring(db, CONTRACT)
    local = A.audit_bundle(db, CONTRACT, number)["deliveries"]["local_signed"]
    dual = A.audit_bundle(db, CONTRACT, number)["deliveries"]["dual_witness"]
    assert local["root"] == dual["root"] == summary["root"]
    assert local["local_signature"]["key_id"].startswith("local:")
    assert {r["witness_id"] for r in dual["receipts"]} == {"W1", "W2"}
    assert {r["signed_at"] for r in dual["receipts"]} == {
        "2030-06-09T10:00:00+00:00", "2030-06-09T10:05:00+00:00",
    }
    for receipt in dual["receipts"]:
        assert A.verify_receipt(receipt, keyring[f"witness:source-anchor-2030-06-09:{receipt['witness_id']}"])
    assert A.verify_receipt(dual["receipts"][0], "00" * 32) is False


def test_forked_witness_keeps_dual_pending_and_local_usable(tmp_path):
    db = seed_appended(tmp_path)
    summary = A.publish_checkpoint(db, CONTRACT, policy="dual_witness")
    number = summary["checkpoint_number"]
    A.simulate_witness_ack(db, CONTRACT, number, "W1")
    result = A.simulate_witness_ack(
        db, CONTRACT, number, "W2", observed_root="ab" * 32, observed_size=summary["tree_size"]
    )
    assert result["accepted"] is False and result["fork"] is True
    dual = A.build_delivery(db, CONTRACT, number, "dual_witness")
    assert dual["status"] == "pending_verification"
    assert len(dual["forks"]) == 1
    assert dual["forks"][0]["detail"]["observed_root"] == "ab" * 32
    assert dual["forks"][0]["detail"]["expected_root"] == summary["root"]
    # The local package is untouched and still verifies.
    keyring = A.export_keyring(db, CONTRACT)
    local = A.audit_bundle(db, CONTRACT, number)
    assert local["deliveries"]["local_signed"]["root"] == summary["root"]
    verification = A.verify_bundle(local, keyring)
    assert verification["ok"] is True
    checks = {c["check"]: c["ok"] for c in verification["checks"]}
    assert checks["local_signature_valid"] is True
    assert checks["dual_status_matches"] is True
    assert A.list_forks(db, CONTRACT)[0]["kind"] == "witness_fork"


def test_fork_is_not_silently_healed_by_a_later_matching_ack(tmp_path):
    db = seed_appended(tmp_path)
    summary = A.publish_checkpoint(db, CONTRACT, policy="dual_witness")
    number = summary["checkpoint_number"]
    A.simulate_witness_ack(db, CONTRACT, number, "W1")
    A.simulate_witness_ack(db, CONTRACT, number, "W2", observed_root="ab" * 32)
    A.simulate_witness_ack(db, CONTRACT, number, "W2")  # retry now agrees
    dual = A.build_delivery(db, CONTRACT, number, "dual_witness")
    assert dual["status"] == "pending_verification"
    assert dual["forks"]


def test_ack_retry_is_idempotent_and_bound_to_the_same_root(tmp_path):
    db = seed_appended(tmp_path)
    summary = A.publish_checkpoint(db, CONTRACT)
    number = summary["checkpoint_number"]
    first = A.simulate_witness_ack(db, CONTRACT, number, "W1")
    retry = A.simulate_witness_ack(db, CONTRACT, number, "W1")
    assert first["signature"] == retry["signature"]
    assert retry["duplicate"] is True
    with pytest.raises(A.AnchorError):
        A.witness_ack(db, CONTRACT, number, "W1", signature="00" * 32)
    with pytest.raises(A.AnchorError):
        A.simulate_witness_ack(db, CONTRACT, number, "W3")


def test_receipt_for_a_later_checkpoint_cannot_impersonate_earlier(tmp_path):
    db = seed_appended(tmp_path)
    first = A.publish_checkpoint(db, CONTRACT)
    add_third_source(tmp_path, db)
    second = A.publish_checkpoint(db, CONTRACT)
    A.simulate_witness_ack(db, CONTRACT, second["checkpoint_number"], "W1", observed_root=first["root"])
    forked = A.simulate_witness_ack(db, CONTRACT, second["checkpoint_number"], "W2", observed_root=first["root"])
    assert forked["fork"] is True
    dual = A.build_delivery(db, CONTRACT, second["checkpoint_number"], "dual_witness")
    assert dual["status"] == "pending_verification"


def test_unregistered_contract_or_mismatched_contract_is_rejected(tmp_path):
    db = seed_appended(tmp_path)
    altered = tmp_path / "altered.json"
    data = json.loads(CONTRACT.read_text())
    data["case_id"] = "some-other-case"
    altered.write_text(json.dumps(data))
    with pytest.raises(A.AnchorError):
        A.publish_checkpoint(db, altered)


# ---------------------------------------------------------------------------
# Crash injection and recovery
# ---------------------------------------------------------------------------


def test_fault_after_root_compute_persists_nothing(tmp_path):
    db = seed_appended(tmp_path)
    with pytest.raises(A.InjectedFault) as exc:
        A.publish_checkpoint(db, CONTRACT, fault="after_root_compute")
    assert exc.value.detail["persisted"] is False
    assert checkpoint_rows(db) == []
    summary = A.publish_checkpoint(db, CONTRACT)
    assert summary["checkpoint_number"] == 1
    assert summary["root"] == exc.value.detail["root"]


def test_fault_after_checkpoint_persist_can_be_resumed(tmp_path):
    db = seed_appended(tmp_path)
    with pytest.raises(A.InjectedFault) as exc:
        A.publish_checkpoint(db, CONTRACT, fault="after_checkpoint_persist")
    number = exc.value.detail["checkpoint_number"]
    [row] = checkpoint_rows(db)
    assert row["number"] == number
    assert row["root"] == exc.value.detail["root"]
    con = sqlite3.connect(db)
    states = [r[0] for r in con.execute("SELECT state FROM anchor_witness_request WHERE checkpoint_number=?", (number,))]
    con.close()
    assert states and set(states) == {"pending"}

    report = A.recover(db, CONTRACT)
    assert any(a["action"] == "dispatch_pending_requests" for a in report["actions"])
    assert len(checkpoint_rows(db)) == 1
    assert checkpoint_rows(db)[0]["root"] == row["root"]
    A.simulate_witness_ack(db, CONTRACT, number, "W1")
    A.simulate_witness_ack(db, CONTRACT, number, "W2")
    assert A.build_delivery(db, CONTRACT, number, "dual_witness")["status"] == "complete"


def test_fault_after_first_witness_receipt_keeps_single_history(tmp_path):
    db = seed_appended(tmp_path)
    with pytest.raises(A.InjectedFault) as exc:
        A.publish_checkpoint(db, CONTRACT, fault="after_first_witness_receipt")
    number = exc.value.detail["checkpoint_number"]
    assert exc.value.detail["witness_acked"] == "W1"
    report = A.recover(db, CONTRACT)
    assert report["latest_checkpoint"] == number
    assert len(checkpoint_rows(db)) == 1
    A.simulate_witness_ack(db, CONTRACT, number, "W2")
    assert A.build_delivery(db, CONTRACT, number, "dual_witness")["status"] == "complete"


def test_signature_arriving_after_a_later_source_cannot_rewrite_history(tmp_path):
    db = seed_appended(tmp_path)
    first = A.publish_checkpoint(db, CONTRACT)
    add_third_source(tmp_path, db)
    second = A.publish_checkpoint(db, CONTRACT)
    assert second["checkpoint_number"] == first["checkpoint_number"] + 1
    # The ACK for the older checkpoint arrives late, after the newer one.
    assert A.simulate_witness_ack(db, CONTRACT, first["checkpoint_number"], "W1")["state"] == "awaiting_witness"
    assert A.simulate_witness_ack(db, CONTRACT, first["checkpoint_number"], "W2")["state"] == "witnessed"
    rows = checkpoint_rows(db)
    assert rows[0]["root"] == first["root"] and rows[0]["tree_size"] == 2
    assert rows[1]["root"] == second["root"] and rows[1]["tree_size"] == 3
    assert A.build_delivery(db, CONTRACT, first["checkpoint_number"], "dual_witness")["status"] == "complete"
    assert A.build_delivery(db, CONTRACT, second["checkpoint_number"], "dual_witness")["status"] == "pending_verification"
    doc = A.consistency_between(db, CONTRACT, first["checkpoint_number"], second["checkpoint_number"])
    assert doc["verified"] is True


def test_recovery_can_advance_to_a_new_checkpoint_without_renumbering(tmp_path):
    db = seed_appended(tmp_path)
    with pytest.raises(A.InjectedFault):
        A.publish_checkpoint(db, CONTRACT, fault="after_checkpoint_persist")
    add_third_source(tmp_path, db)
    report = A.recover(db, CONTRACT, advance=True)
    assert report["published"]["checkpoint_number"] == 2
    assert report["published"]["tree_size"] == 3
    rows = checkpoint_rows(db)
    assert [r["number"] for r in rows] == [1, 2]
    assert rows[0]["tree_size"] == 2
    doc = A.consistency_between(db, CONTRACT, 1, 2)
    assert doc["verified"] is True


def test_recovery_redispatch_does_not_duplicate_requests(tmp_path):
    db = seed_appended(tmp_path)
    with pytest.raises(A.InjectedFault):
        A.publish_checkpoint(db, CONTRACT, fault="after_checkpoint_persist")
    A.recover(db, CONTRACT)
    con = sqlite3.connect(db)
    count = con.execute("SELECT count(*) FROM anchor_witness_request").fetchone()[0]
    con.close()
    assert count == 2
    A.recover(db, CONTRACT)
    con = sqlite3.connect(db)
    assert con.execute("SELECT count(*) FROM anchor_witness_request").fetchone()[0] == 2
    con.close()


def test_recovery_flags_a_rewritten_prefix_instead_of_rewriting_it(tmp_path):
    db = seed_appended(tmp_path)
    summary = A.publish_checkpoint(db, CONTRACT)
    case = json.loads(CONTRACT.read_text())["case_id"]
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    leaf = dict(con.execute("SELECT * FROM anchor_leaf WHERE case_id=? ORDER BY leaf_index", (case,)).fetchone())
    con.execute("UPDATE anchor_leaf SET leaf_hash=? WHERE case_id=? AND leaf_index=0", ("00" * 32, case))
    con.commit()
    con.close()
    report = A.recover(db, CONTRACT)
    assert any(a["action"] == "mark_forked" for a in report["actions"])
    rows = checkpoint_rows(db)
    assert rows[0]["root"] == summary["root"]  # never rewritten
    assert rows[0]["state"] == "forked"
    assert A.list_forks(db, CONTRACT)[0]["kind"] == "recovery_prefix_mismatch"


# ---------------------------------------------------------------------------
# Concurrent import
# ---------------------------------------------------------------------------


def test_concurrent_appends_get_distinct_persistent_leaf_indices(tmp_path):
    import threading

    db = seed_appended(tmp_path)
    errors = []

    def worker(i):
        try:
            A.append_source(db, CONTRACT, f"concurrent-{i}", f"{i:064x}")
        except Exception as exc:  # pragma: no cover - only on a real race
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    con = sqlite3.connect(db)
    indices = [r[0] for r in con.execute("SELECT leaf_index FROM anchor_leaf ORDER BY leaf_index")]
    con.close()
    assert indices == list(range(14))
    summary = A.publish_checkpoint(db, CONTRACT)
    assert summary["tree_size"] == 14
    assert A.verify_bundle(A.audit_bundle(db, CONTRACT, summary["checkpoint_number"]))["ok"] is True


def test_concurrent_append_from_ingest_converges_to_one_leaf_per_source(tmp_path):
    import threading

    db = seed(tmp_path)
    errors = []
    results = []

    def worker():
        try:
            results.append(A.append_from_ingest(db, CONTRACT))
        except Exception as exc:  # pragma: no cover - only on a real race
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    con = sqlite3.connect(db)
    assert con.execute("SELECT count(*) FROM anchor_leaf").fetchone()[0] == 2
    con.close()
    total_appended = sum(len(r["appended"]) for r in results)
    assert total_appended == 2


def test_corrections_are_appended_and_old_leaves_remain(tmp_path):
    db = seed_appended(tmp_path)
    first = A.publish_checkpoint(db, CONTRACT)
    case = json.loads(CONTRACT.read_text())["case_id"]
    target = A.durable_source_id(case, 1)
    A.append_correction(
        db, CONTRACT, "correction-1", target, kind="revoke", reason="wrong scale"
    )
    A.append_correction(
        db, CONTRACT, "correction-2", target, kind="replace",
        bytes_sha256="cc" * 32, reason="re-scan",
    )
    second = A.publish_checkpoint(db, CONTRACT)
    assert second["tree_size"] == first["tree_size"] + 2
    leaves = second["leaves"]
    assert leaves[0]["source_id"] == target  # never mutated
    assert leaves[2]["kind"] == "revoke" and leaves[2]["source_id"] == "correction-1"
    assert leaves[3]["kind"] == "replace" and leaves[3]["source_id"] == "correction-2"
    doc = A.consistency_between(db, CONTRACT, first["checkpoint_number"], second["checkpoint_number"])
    assert doc["verified"] is True
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    status = dict(con.execute(
        "SELECT status FROM anchor_source WHERE case_id=? AND source_id=?", (case, target)
    ).fetchone())["status"]
    con.close()
    assert status == "replaced"
    bundle = A.audit_bundle(db, CONTRACT, second["checkpoint_number"], consistency_from=first["checkpoint_number"])
    assert A.verify_bundle(bundle)["ok"] is True


def test_correction_cannot_target_an_unknown_source(tmp_path):
    db = seed_appended(tmp_path)
    with pytest.raises(A.AnchorError):
        A.append_correction(db, CONTRACT, "fix", "does-not-exist", kind="revoke")


def test_full_audit_scenario_with_two_real_evidence_packages(tmp_path):
    """The contract's two complete legal deliveries, end to end.

    Both packages cite the same original bytes but have different trust
    issuers, credentials and issue times.  When the second witness sees a
    different root the dual package stays pending and shows the fork, while
    the local package still verifies against its original root.
    """

    db = seed(tmp_path)
    A.append_from_ingest(db, CONTRACT)
    keyring = None

    first = A.publish_checkpoint(db, CONTRACT, policy="local_signed")
    number = first["checkpoint_number"]
    A.simulate_witness_ack(db, CONTRACT, number, "W1", signed_at="2030-06-09T09:00:00+00:00")
    # W2 sees a forked root and must not be able to force a rewrite.
    fork = A.simulate_witness_ack(
        db, CONTRACT, number, "W2",
        observed_root="ee" * 32, observed_size=first["tree_size"],
        signed_at="2030-06-09T09:10:00+00:00",
    )
    assert fork["fork"] is True
    keyring = A.export_keyring(db, CONTRACT)

    # A genuinely matching W2 is a separate, later delivery attempt.
    A.simulate_witness_ack(db, CONTRACT, number, "W2", signed_at="2030-06-09T09:20:00+00:00")

    package = A.audit_bundle(db, CONTRACT, number)
    local = package["deliveries"]["local_signed"]
    dual = package["deliveries"]["dual_witness"]
    assert local["status"] == "complete"
    assert local["root"] == first["root"]
    assert dual["status"] == "pending_verification"
    assert dual["root"] == first["root"]  # never silently rewritten
    assert dual["forks"]
    receipt_times = {r["witness_id"]: r["signed_at"] for r in dual["receipts"]}
    assert receipt_times["W1"] != receipt_times["W2"]

    verification = A.verify_bundle(package, keyring)
    assert verification["ok"] is True
    checks = {c["check"]: c["ok"] for c in verification["checks"]}
    assert checks["local_signature_valid"] is True
    assert checks["dual_status_matches"] is True

    # The same original bytes are cited by both packages.
    assert package["deliveries"]["local_signed"]["snapshot_sha256"] == dual["snapshot_sha256"]
    assert all(
        leaf["payload"]["kind"] == "source"
        for leaf in package["leaves"]
    )

    # Later appends produce a prefix-consistent checkpoint the auditor checks
    # with only the two roots, sizes and proof.
    add_third_source(tmp_path, db)
    later = A.publish_checkpoint(db, CONTRACT)
    doc = A.consistency_between(db, CONTRACT, number, later["checkpoint_number"])
    assert doc["verified"] is True
    assert verify_consistency(
        doc["old_tree_size"], doc["new_tree_size"], doc["old_root"], doc["new_root"], doc["proof"]
    )
    later_bundle = A.audit_bundle(
        db, CONTRACT, later["checkpoint_number"], consistency_from=number
    )
    assert A.verify_bundle(later_bundle, keyring)["ok"] is True


def test_inclusion_for_any_source_in_current_and_named_tree(tmp_path):
    db = seed_appended(tmp_path)
    case = json.loads(CONTRACT.read_text())["case_id"]
    first_source = A.durable_source_id(case, 1)
    current = A.inclusion_for(db, CONTRACT, first_source)
    assert current["leaf_index"] == 0
    assert current["tree_size"] == 2
    assert current["verified"] is True
    assert verify_inclusion(
        current["leaf_hash"], current["leaf_index"], current["tree_size"],
        current["proof"], current["root"], DomainTags(),
    )
    old = A.publish_checkpoint(db, CONTRACT)
    add_third_source(tmp_path, db)
    A.publish_checkpoint(db, CONTRACT)
    # Pinned to the older checkpoint the path still matches that smaller tree.
    pinned = A.inclusion_for(db, CONTRACT, first_source, old["checkpoint_number"])
    assert pinned["tree_size"] == 2 and pinned["root"] == old["root"] and pinned["verified"]
    with pytest.raises(A.AnchorError):
        A.inclusion_for(db, CONTRACT, "not-a-source")


def test_bundle_inclusion_must_be_bound_to_the_checkpoint(tmp_path):
    db = seed_appended(tmp_path)
    summary = A.publish_checkpoint(db, CONTRACT)
    bundle = A.audit_bundle(db, CONTRACT, summary["checkpoint_number"])
    # An inclusion document that cites a different root/size is rejected even
    # if its path happens to verify on its own terms.
    sid = next(iter(bundle["inclusions"]))
    altered = json.loads(json.dumps(bundle))
    altered["inclusions"][sid]["tree_size"] = summary["tree_size"] + 1
    result = A.verify_bundle(altered)
    assert result["ok"] is False
    assert {c["check"]: c["ok"] for c in result["checks"]}["inclusions_bound_to_checkpoint"] is False
    altered2 = json.loads(json.dumps(bundle))
    altered2["inclusions"][sid]["leaf_index"] = 1 - altered2["inclusions"][sid]["leaf_index"]
    assert {c["check"]: c["ok"] for c in A.verify_bundle(altered2)["checks"]}["inclusions_bound_to_checkpoint"] is False


# ---------------------------------------------------------------------------
# Bundle and independent verification
# ---------------------------------------------------------------------------


def test_bundle_reports_roots_proofs_receipts_and_forks(tmp_path):
    db = seed_appended(tmp_path)
    first = A.publish_checkpoint(db, CONTRACT)
    add_third_source(tmp_path, db)
    second = A.publish_checkpoint(db, CONTRACT)
    A.simulate_witness_ack(db, CONTRACT, second["checkpoint_number"], "W1")
    A.simulate_witness_ack(
        db, CONTRACT, second["checkpoint_number"], "W2",
        observed_root="cd" * 32, observed_size=second["tree_size"],
    )
    bundle = A.audit_bundle(
        db, CONTRACT, second["checkpoint_number"], consistency_from=first["checkpoint_number"]
    )
    assert bundle["checkpoint"]["number"] == second["checkpoint_number"]
    assert bundle["checkpoint"]["root"] == second["root"]
    assert bundle["consistency"]["old_root"] == first["root"]
    assert bundle["consistency"]["new_root"] == second["root"]
    assert bundle["deliveries"]["local_signed"]["status"] == "complete"
    assert bundle["deliveries"]["dual_witness"]["status"] == "pending_verification"
    assert bundle["deliveries"]["dual_witness"]["forks"]
    kinds = {event["kind"] for event in bundle["events"]}
    assert {"leaf_appended", "witness_fork", "local_delivery_signed"} <= kinds
    assert "anchor-verify" in bundle["verify"]["command"]
    result = A.verify_bundle(bundle, A.export_keyring(db, CONTRACT))
    assert result["ok"] is True
    checks = {c["check"]: c for c in result["checks"]}
    assert checks["consistency_verifies"]["ok"] is True
    assert checks["dual_status_matches"]["ok"] is True
    assert checks["local_signature_valid"]["ok"] is True


def test_verifier_needs_only_roots_sizes_and_proof_for_consistency(tmp_path):
    db = seed_appended(tmp_path)
    first = A.publish_checkpoint(db, CONTRACT)
    add_third_source(tmp_path, db)
    second = A.publish_checkpoint(db, CONTRACT)
    bundle = A.audit_bundle(db, CONTRACT, second["checkpoint_number"], consistency_from=first["checkpoint_number"])
    # Strip everything except what a minimal verifier would receive.
    minimal = {
        k: bundle[k]
        for k in ("leaf_tag", "node_tag", "checkpoint", "leaves", "inclusions", "consistency", "deliveries", "case_id")
    }
    assert A.verify_bundle(minimal)["ok"] is True
    tampered = json.loads(json.dumps(minimal))
    tampered["leaves"][0]["payload"]["import_version"] = "9"
    result = A.verify_bundle(tampered)
    assert result["ok"] is False
    checks = {c["check"]: c["ok"] for c in result["checks"]}
    assert checks["leaf_hash_matches_payload"] is False


def test_bundle_truncated_consistency_proof_fails(tmp_path):
    db = seed_appended(tmp_path)
    first = A.publish_checkpoint(db, CONTRACT)
    add_third_source(tmp_path, db)
    second = A.publish_checkpoint(db, CONTRACT)
    bundle = A.audit_bundle(db, CONTRACT, second["checkpoint_number"], consistency_from=first["checkpoint_number"])
    bundle["consistency"]["proof"] = bundle["consistency"]["proof"][:-1]
    result = A.verify_bundle(bundle)
    assert result["ok"] is False
    assert {c["check"]: c["ok"] for c in result["checks"]}["consistency_verifies"] is False


def test_write_bundle_emits_json_and_markdown_with_verification(tmp_path):
    db = seed_appended(tmp_path)
    summary = A.publish_checkpoint(db, CONTRACT)
    A.simulate_witness_ack(db, CONTRACT, summary["checkpoint_number"], "W1")
    A.simulate_witness_ack(db, CONTRACT, summary["checkpoint_number"], "W2")
    bundle = A.audit_bundle(db, CONTRACT, summary["checkpoint_number"])
    out = tmp_path / "out" / "bundle.json"
    verification = A.verify_bundle(bundle, A.export_keyring(db, CONTRACT))
    json_path, md_path = A.write_bundle(bundle, out, verification)
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["checkpoint"]["root"] == summary["root"]
    text = md_path.read_text(encoding="utf-8")
    assert summary["root"] in text
    assert "一致性" in text or "来源锚定审计报告" in text
    assert "anchor-verify" in text
    assert "通过" in text


def test_cli_verify_accepts_a_written_bundle(tmp_path, capsys):
    import contextlib

    from coldhandoff.__main__ import main

    db = seed_appended(tmp_path)
    summary = A.publish_checkpoint(db, CONTRACT)
    bundle = A.audit_bundle(db, CONTRACT, summary["checkpoint_number"])
    path = tmp_path / "bundle.json"
    A.write_bundle(bundle, path)

    def run(*argv):
        import sys

        old = sys.argv
        sys.argv = ["coldhandoff", *argv]
        try:
            main()
        except SystemExit as exc:
            assert exc.code == 0
        finally:
            sys.argv = old

    run("anchor-verify", "--bundle", str(path))
    output = capsys.readouterr().out
    assert '"ok": true' in output
