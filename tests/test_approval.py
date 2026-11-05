"""Human approval records bound to a report. No Docker."""

import hashlib
import json

import pytest

from boundaryrun.approval import FILENAME, Approval, ApprovalError, check_approval, record_approval
from boundaryrun.cli import main
from boundaryrun.evidence import KEY_ENV, verify_run

from .test_evidence import _write_run


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.delenv(KEY_ENV, raising=False)
    r = _write_run(tmp_path)
    report = json.loads((r / "report.json").read_text())
    report["verdict"] = {"status": "needs_review", "reasons": ["static analysis: patch introduced x"]}
    (r / "report.json").write_text(json.dumps(report, indent=2))
    return r


def test_record_writes_a_record_bound_to_the_report(run):
    a = record_approval(run, reviewer="  Iris Li ", decision="approve", note=" looks right ")
    assert a.investigation_id == run.name and a.verdict == "needs_review" and a.decision == "approve"
    assert a.reviewer == "Iris Li" and a.note == "looks right" and a.hmac is None
    assert a.report_sha256 == hashlib.sha256((run / "report.json").read_bytes()).hexdigest()
    on_disk = Approval.model_validate_json((run / FILENAME).read_text())
    assert on_disk == a
    ac = check_approval(run)
    assert ac.bound is True and ac.signature is None and ac.problem is None and ac.approval == a


def test_record_requires_a_reviewer_and_a_report(run, tmp_path):
    with pytest.raises(ApprovalError, match="reviewer"):
        record_approval(run, reviewer="   ", decision="approve")
    with pytest.raises(ApprovalError, match="no report.json"):
        record_approval(tmp_path / "nothing", reviewer="x", decision="approve")
    assert not (run / FILENAME).exists()


def test_no_approval_is_distinguishable_from_a_bad_one(run):
    ac = check_approval(run)
    assert ac.approval is None and ac.bound is None and ac.signature is None and ac.problem is None
    (run / FILENAME).write_text("{not json")
    ac = check_approval(run)
    assert ac.approval is None and ac.bound is False and "invalid" in ac.problem


def test_rewritten_report_orphans_the_approval(run):
    record_approval(run, reviewer="r", decision="approve")
    report = json.loads((run / "report.json").read_text())
    report["verdict"]["status"] = "verified"
    (run / "report.json").write_text(json.dumps(report, indent=2))
    ac = check_approval(run)
    assert ac.bound is False and "different report.json" in ac.problem
    v = verify_run(run)
    assert any(c.name == "approval" and c.ok is False for c in v.checks) and not v.ok


def test_intact_unsigned_approval_is_reported_but_not_counted_as_verified(run):
    record_approval(run, reviewer="r", decision="approve")
    v = verify_run(run)
    c = [c for c in v.checks if c.name == "approval"][0]
    assert c.ok is None and "approve by r" in c.detail and "unsigned" in c.detail and v.ok


def test_signature_is_required_once_the_operator_key_is_set(run, monkeypatch):
    record_approval(run, reviewer="r", decision="approve")  # unsigned: no key at record time
    monkeypatch.setenv(KEY_ENV, "operator-secret")
    ac = check_approval(run)
    assert ac.bound is True and ac.signature is False and "unsigned" in ac.problem
    signed = record_approval(run, reviewer="r", decision="approve")
    assert signed.hmac and len(signed.hmac) == 64
    ac = check_approval(run)
    assert ac.signature is True and ac.problem is None
    monkeypatch.setenv(KEY_ENV, "wrong")
    ac = check_approval(run)
    assert ac.signature is False and "does not match" in ac.problem
    monkeypatch.delenv(KEY_ENV)
    assert check_approval(run).signature is None  # present but not checkable here


def test_editing_a_signed_approval_breaks_its_signature(run, monkeypatch):
    monkeypatch.setenv(KEY_ENV, "operator-secret")
    record_approval(run, reviewer="r", decision="reject", note="no")
    text = (run / FILENAME).read_text().replace('"reject"', '"approve"')
    (run / FILENAME).write_text(text)
    ac = check_approval(run)
    assert ac.approval.decision == "approve" and ac.signature is False and "does not match" in ac.problem


def test_rejection_is_recorded_as_such(run):
    a = record_approval(run, reviewer="r", decision="reject", note="backdoor")
    assert a.decision == "reject" and check_approval(run).approval.decision == "reject"


def test_cli_approve_and_reject(run, capsys):
    assert main(["approve", str(run), "--reviewer", "Iris", "--note", "ok"]) == 0
    out = capsys.readouterr().out
    assert "approve recorded" in out and "verdict needs_review" in out and "unsigned" in out
    assert main(["approve", str(run), "--reviewer", "Iris", "--reject"]) == 0
    assert check_approval(run).approval.decision == "reject"
    assert main(["approve", str(run), "--reviewer", " "]) == 4
