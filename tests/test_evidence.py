"""Tamper evidence: audit hash chain, artifact hashes, report HMAC. No Docker."""

import hashlib
import json

import pytest

from boundaryrun.evidence import GENESIS, KEY_ENV, chain_records, sign, verify_chain, verify_run


def _records(n=4):
    return [
        {"seq": i, "timestamp": f"2026-11-05T00:00:0{i}+00:00", "tool": "read_file", "input": {"path": f"app/{i}.py"},
         "decision": {"effect": "allow", "rule": "read.allow", "reason": "ok"}, "reference_decision": None,
         "outcome": "executed", "output_bytes": 10, "output_sha256": "ab" * 32, "error": None, "duration_ms": 1.0}
        for i in range(1, n + 1)
    ]


def test_chain_is_deterministic_and_verifies():
    lines, head = chain_records(_records())
    ok, got_head, problem = verify_chain(lines)
    assert ok and problem is None and got_head == head
    assert json.loads(lines[0])["prev_hash"] == GENESIS
    again, head2 = chain_records(_records())
    assert again == lines and head2 == head


def test_hash_definition_is_language_independent():
    """hash_n = sha256(hash_{n-1} || line without its trailing record_hash member)."""
    lines, _ = chain_records(_records(2))
    text0 = lines[0][: lines[0].rindex(',"record_hash":')] + "}"
    h0 = hashlib.sha256((GENESIS + text0).encode()).hexdigest()
    assert json.loads(lines[0])["record_hash"] == h0
    text1 = lines[1][: lines[1].rindex(',"record_hash":')] + "}"
    assert json.loads(lines[1])["record_hash"] == hashlib.sha256((h0 + text1).encode()).hexdigest()


@pytest.mark.parametrize("mutation", ["edit", "delete", "insert", "reorder", "truncate_tail"])
def test_any_mutation_breaks_the_chain(mutation):
    lines, head = chain_records(_records())
    if mutation == "edit":
        lines[1] = lines[1].replace('"outcome":"executed"', '"outcome":"denied"')
    elif mutation == "delete":
        del lines[1]
    elif mutation == "insert":
        extra, _ = chain_records(_records(1))
        lines.insert(1, extra[0])
    elif mutation == "reorder":
        lines[1], lines[2] = lines[2], lines[1]
    elif mutation == "truncate_tail":
        lines = lines[:-1]
    ok, got_head, problem = verify_chain(lines)
    assert (not ok) or got_head != head
    if not ok:
        assert problem


def _write_run(tmp_path, *, key=None):
    recs = _records(3)
    lines, head = chain_records(recs)
    run = tmp_path / "inv-20260101T000000Z-abcdef"
    run.mkdir()
    (run / "audit.jsonl").write_text("".join(ln + "\n" for ln in lines))
    (run / "patch.diff").write_text("--- a/app/main.py\n+++ b/app/main.py\n@@ -1 +1 @@\n-x\n+y\n")
    report = {
        "investigation_id": run.name,
        "tool_requests": recs,
        "patch": {"files": [{"path": "app/main.py", "change": "modified", "in_write_scope": True}],
                  "diff": (run / "patch.diff").read_text()},
        "artifacts": {name: hashlib.sha256((run / name).read_bytes()).hexdigest() for name in ("audit.jsonl", "patch.diff")},
        "audit_chain_head": head,
    }
    (run / "report.json").write_text(json.dumps(report, indent=2))
    if key:
        (run / "report.hmac").write_text(sign((run / "report.json").read_bytes(), key) + "\n")
    return run


def test_verify_run_passes_on_an_intact_run(tmp_path):
    v = verify_run(_write_run(tmp_path))
    assert v.ok, [c for c in v.checks if c.ok is False]
    assert {c.name for c in v.checks} >= {"artifact audit.jsonl", "artifact patch.diff", "audit chain",
                                          "chain head in report", "report tool_requests vs audit.jsonl",
                                          "patch.diff vs report.patch.diff", "report HMAC"}


def test_verify_run_catches_a_rewritten_audit_record(tmp_path):
    run = _write_run(tmp_path)
    text = (run / "audit.jsonl").read_text().replace('"outcome":"executed"', '"outcome":"denied"', 1)
    (run / "audit.jsonl").write_text(text)
    v = verify_run(run)
    failed = {c.name for c in v.checks if c.ok is False}
    assert not v.ok and {"artifact audit.jsonl", "audit chain"} <= failed


def test_verify_run_catches_a_report_edited_to_match_a_rewritten_log(tmp_path):
    """Rewriting the log and re-chaining it, then updating the artifact hash, still disagrees
    with the records embedded in the report."""
    run = _write_run(tmp_path)
    recs = _records(3)
    recs[0]["outcome"] = "denied"
    lines, head = chain_records(recs)
    (run / "audit.jsonl").write_text("".join(ln + "\n" for ln in lines))
    report = json.loads((run / "report.json").read_text())
    report["artifacts"]["audit.jsonl"] = hashlib.sha256((run / "audit.jsonl").read_bytes()).hexdigest()
    report["audit_chain_head"] = head
    (run / "report.json").write_text(json.dumps(report))
    v = verify_run(run)
    assert not v.ok
    assert any(c.name == "report tool_requests vs audit.jsonl" and c.ok is False for c in v.checks)


def test_verify_run_catches_a_swapped_diff(tmp_path):
    run = _write_run(tmp_path)
    (run / "patch.diff").write_text("--- a/app/main.py\n+++ b/app/main.py\n@@ -1 +1 @@\n-x\n+z\n")
    v = verify_run(run)
    failed = {c.name for c in v.checks if c.ok is False}
    assert {"artifact patch.diff", "patch.diff vs report.patch.diff"} <= failed


def test_hmac_requires_the_operator_key_and_detects_report_edits(tmp_path, monkeypatch):
    key = b"operator-secret"
    run = _write_run(tmp_path, key=key)
    monkeypatch.delenv(KEY_ENV, raising=False)
    unverifiable = [c for c in verify_run(run).checks if c.name == "report HMAC"][0]
    assert unverifiable.ok is None
    monkeypatch.setenv(KEY_ENV, key.decode())
    assert verify_run(run).ok
    report = json.loads((run / "report.json").read_text())
    report["verdict"] = {"status": "verified"}
    (run / "report.json").write_text(json.dumps(report, indent=2))
    v = verify_run(run)
    assert any(c.name == "report HMAC" and c.ok is False for c in v.checks)
    monkeypatch.setenv(KEY_ENV, "wrong")
    assert any(c.name == "report HMAC" and c.ok is False for c in verify_run(run).checks)


def test_unsigned_run_fails_when_operator_expects_signatures(tmp_path, monkeypatch):
    run = _write_run(tmp_path)
    monkeypatch.setenv(KEY_ENV, "k")
    assert any(c.name == "report HMAC" and c.ok is False for c in verify_run(run).checks)
