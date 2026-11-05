"""Human approval records: bound to one report, attributable, optionally signed, and the only
thing that releases a `needs_review` run. No Docker; reports come from the viewer's fixtures.
"""

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from boundaryrun.approval import FILENAME, Approval, ApprovalError, check_approval, record_approval
from boundaryrun.evidence import KEY_ENV, verify_run
from boundaryrun.pipeline import Report
from boundaryrun.propose import ProposalError, _require_releasable, render_pr_body
from boundaryrun.verify import Status, Verdict

from .conftest import ROOT

FIXTURE_EVAL = ROOT / "web" / "tests" / "fixtures" / "runs" / "eval-20261105T023154Z"
VERIFIED_RUN = FIXTURE_EVAL / "inv-20261105T023154Z-8b523b"
REVIEW_RUN = FIXTURE_EVAL / "inv-20261105T023450Z-f14bac"


@pytest.fixture
def run(tmp_path) -> Path:
    dst = tmp_path / REVIEW_RUN.name
    shutil.copytree(REVIEW_RUN, dst)
    return dst


def report_of(run_dir: Path) -> Report:
    return Report.model_validate(json.loads((run_dir / "report.json").read_text()))


def test_fixture_reports_have_the_verdicts_these_tests_rely_on():
    assert report_of(VERIFIED_RUN).verdict.status == Status.VERIFIED
    assert report_of(REVIEW_RUN).verdict.status == Status.NEEDS_REVIEW


def test_record_binds_the_decision_to_the_exact_report(run):
    a = record_approval(run, reviewer="  Ada Reviewer ", decision="approve", note=" looked at the diff ")
    assert a.reviewer == "Ada Reviewer" and a.note == "looked at the diff"
    assert a.verdict == "needs_review" and a.investigation_id == run.name
    assert a.report_sha256 == hashlib.sha256((run / "report.json").read_bytes()).hexdigest()
    assert a.hmac is None  # no operator key in this test
    on_disk = Approval.model_validate_json((run / FILENAME).read_text())
    assert on_disk == a
    chk = check_approval(run)
    assert chk.bound is True and chk.signature is None and chk.problem is None


def test_rewriting_the_report_orphans_the_approval(run):
    record_approval(run, reviewer="ada", decision="approve")
    rep = json.loads((run / "report.json").read_text())
    rep["verdict"]["status"] = "verified"
    (run / "report.json").write_text(json.dumps(rep))
    chk = check_approval(run)
    assert chk.bound is False and "different report.json" in chk.problem
    with pytest.raises(ProposalError, match="different report"):
        from boundaryrun.propose import propose

        propose(run, remote="file:///nowhere", base_branch="main", allow_simulated=True)


def test_approval_must_be_attributable(run):
    with pytest.raises(ApprovalError, match="attributable"):
        record_approval(run, reviewer="   ", decision="approve")
    assert not (run / FILENAME).exists()


def test_approval_needs_a_report(tmp_path):
    with pytest.raises(ApprovalError, match="no report.json"):
        record_approval(tmp_path, reviewer="ada", decision="approve")


def test_no_approval_is_not_a_problem(run):
    chk = check_approval(run)
    assert chk.approval is None and chk.bound is None and chk.problem is None
    assert not any(c.name == "approval" for c in verify_run(run).checks)


def test_unreadable_approval_is_reported_not_ignored(run):
    (run / FILENAME).write_text("{not json")
    chk = check_approval(run)
    assert chk.approval is None and chk.bound is False and "invalid" in chk.problem
    assert any(c.name == "approval" and c.ok is False for c in verify_run(run).checks)


def test_signed_approval_requires_the_key_and_detects_edits(run, monkeypatch):
    monkeypatch.setenv(KEY_ENV, "operator-secret")
    a = record_approval(run, reviewer="ada", decision="approve")
    assert a.hmac
    chk = check_approval(run)
    assert chk.bound and chk.signature is True and chk.problem is None
    # a forged reviewer name under the same key fails the signature
    forged = a.model_copy(update={"reviewer": "mallory"})
    (run / FILENAME).write_text(forged.model_dump_json(indent=2))
    chk = check_approval(run)
    assert chk.signature is False and "signature does not match" in chk.problem
    # with the key set, an unsigned approval is refused too
    (run / FILENAME).write_text(a.model_copy(update={"hmac": None}).model_dump_json(indent=2))
    chk = check_approval(run)
    assert chk.signature is False and "unsigned" in chk.problem
    monkeypatch.delenv(KEY_ENV)
    assert check_approval(run).signature is None  # unsigned is fine when no key is expected


def test_verify_run_reports_the_approval(run, monkeypatch):
    record_approval(run, reviewer="ada", decision="reject", note="backdoor")
    chk = [c for c in verify_run(run).checks if c.name == "approval"]
    assert len(chk) == 1 and chk[0].ok is None and "reject by ada" in chk[0].detail and "unsigned" in chk[0].detail
    monkeypatch.setenv(KEY_ENV, "k")
    record_approval(run, reviewer="ada", decision="approve")
    chk = next(c for c in verify_run(run).checks if c.name == "approval")
    assert chk.ok is True and "signed" in chk.detail


# -- release gate ------------------------------------------------------------------------


def _approval(decision, verdict="needs_review"):
    return Approval(investigation_id="x", report_sha256="0" * 64, verdict=verdict, decision=decision,
                    reviewer="ada", recorded_at="2026-11-05T00:00:00+00:00")


def test_needs_review_releases_only_with_an_approval():
    r = report_of(REVIEW_RUN).model_copy(update={"attack": None})
    with pytest.raises(ProposalError, match="needs_review.*no human approval"):
        _require_releasable(r, None, allow_simulated=True)
    _require_releasable(r, _approval("approve"), allow_simulated=True)


def test_rejection_blocks_even_a_verified_run():
    r = report_of(VERIFIED_RUN).model_copy(update={"attack": None})
    _require_releasable(r, None, allow_simulated=True)
    with pytest.raises(ProposalError, match="rejected by ada"):
        _require_releasable(r, _approval("reject", "verified"), allow_simulated=True)


@pytest.mark.parametrize("status", [Status.NOT_REMEDIATED, Status.REGRESSION, Status.SCOPE_VIOLATION, Status.INCONCLUSIVE,
                                    Status.NO_PATCH])
def test_an_approval_cannot_release_a_failed_verdict(status):
    r = report_of(VERIFIED_RUN).model_copy(update={"attack": None, "verdict": Verdict(status=status, reasons=["r"])})
    with pytest.raises(ProposalError, match=f"'{status.value}', not 'verified'"):
        _require_releasable(r, _approval("approve", status.value), allow_simulated=True)


def test_pr_body_states_the_approval_and_the_requirements():
    from boundaryrun.requirements import RequirementOutcome

    r = report_of(REVIEW_RUN).model_copy(update={"requirements": [
        RequirementOutcome(id="R1", threat="T1", status="satisfied", evidence=["e"]),
        RequirementOutcome(id="R3", threat="T2", status="not_satisfied", evidence=["e"]),
    ]})
    body = render_pr_body(r, _approval("approve").model_copy(update={"note": "reviewed the seed table", "hmac": "ab"}),
                          "BoundaryRun Agent <agent@boundaryrun.invalid>")
    assert "Human approval: **approve** by ada" in body and "(reviewed the seed table)" in body and "and signed." in body
    assert "| R1 | T1 | satisfied |" in body and "| R3 | T2 | not_satisfied |" in body
    assert "Opened by `BoundaryRun Agent <agent@boundaryrun.invalid>`" in body
    assert "unverified claim" in body
    assert render_pr_body(r, None, "id").count("Human approval") == 0
