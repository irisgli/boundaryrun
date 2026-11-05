"""Task-scoped requirements: loading, what the agent sees, and assessment from evidence. No Docker."""

import pytest

from boundaryrun.requirements import ThreatModel, assess, load_threat_model, task_context
from boundaryrun.sandbox import ProbeCheck, ProbeResult, ProbeRun
from boundaryrun.static import StaticFinding, StaticScan, compare
from boundaryrun.verify import FileChange, PatchInfo, Status, decide

from .conftest import SCENARIO
from .test_verdict import probe as verdict_probe, suite

CROSS = ["cross_tenant:bob->doc1", "cross_tenant:bob->doc2", "cross_tenant:alice->doc3"]
LEGIT = ["legit:alice->doc1", "legit:carol->doc1", "legit:bob->doc3"]


def probe(*, cross_blocked=True, legit_ok=True, omit: set[str] = frozenset()) -> ProbeRun:
    checks = [
        ProbeCheck(name=n, kind="unauthorized", status_code=404 if cross_blocked else 200,
                   content_returned=not cross_blocked, outcome="pass" if cross_blocked else "fail")
        for n in CROSS if n not in omit
    ] + [
        ProbeCheck(name=n, kind="legitimate", status_code=200 if legit_ok else 404,
                   content_returned=legit_ok, outcome="pass" if legit_ok else "fail")
        for n in LEGIT if n not in omit
    ]
    return ProbeRun(ok=True, result=ProbeResult(healthy=True, error=None, checks=checks), duration_s=1)


def scan(*rules) -> StaticScan:
    return StaticScan(status="completed", findings=[
        StaticFinding(rule_id=r, severity="WARNING", path="app/main.py", line=1, message="m", snippet="s") for r in rules
    ])


@pytest.fixture(scope="module")
def tm() -> ThreatModel:
    return load_threat_model(SCENARIO / "threat_model.toml")


def test_scenario_threat_model_loads(tm, scenario):
    assert scenario.threat_model == tm
    assert [r.id for r in tm.requirements] == ["R1", "R2", "R3", "R4"]
    assert [r.id for r in tm.for_task()] == ["R1", "R2", "R3"]
    assert {r.threat for r in tm.requirements} <= {t.id for t in tm.threats}


def _write(tmp_path, body: str):
    p = tmp_path / "threat_model.toml"
    p.write_text(body)
    return p


BASE = '[[threats]]\nid = "T1"\ndescription = "d"\n'


@pytest.mark.parametrize(
    "body,match",
    [
        (BASE + '[[requirements]]\nid = "R1"\nthreat = "T9"\nstatement = "s"\nevidence = { probe_checks = ["c"] }\n',
         "unknown threat"),
        (BASE + '[[requirements]]\nid = "R1"\nthreat = "T1"\nstatement = "s"\n', "no evidence"),
        (BASE + '[[requirements]]\nid = "R1"\nthreat = "T1"\nstatement = "s"\nevidence = { probe_checks = ["c"] }\n'
                '[[requirements]]\nid = "R1"\nthreat = "T1"\nstatement = "t"\nevidence = { probe_checks = ["c"] }\n',
         "duplicate"),
    ],
)
def test_load_rejects_malformed_models(tmp_path, body, match):
    with pytest.raises(ValueError, match=match):
        load_threat_model(_write(tmp_path, body))


def test_load_rejects_unknown_keys(tmp_path):
    body = BASE + '[[requirements]]\nid = "R1"\nthreat = "T1"\nstatement = "s"\npriority = 1\nevidence = { probe_checks = ["c"] }\n'
    with pytest.raises(ValueError):
        load_threat_model(_write(tmp_path, body))


def test_enforced_elsewhere_needs_no_evidence(tmp_path):
    body = BASE + '[[requirements]]\nid = "R1"\nthreat = "T1"\nstatement = "s"\nenforced_elsewhere = true\n'
    tm = load_threat_model(_write(tmp_path, body))
    assert tm.for_task() == [] and task_context(tm) == ""


def test_task_context_shows_only_task_requirements_with_their_threats(tm):
    text = task_context(tm)
    assert text.startswith("Security requirements for this task (from the trusted scenario threat model")
    for rid in ("R1", "R2", "R3"):
        assert f"- {rid} (threat T" in text
    assert "R4" not in text and "rate limiting" not in text
    assert "guessing its id" in text  # threat description travels with the requirement
    assert task_context(ThreatModel()) == ""


def test_assess_satisfied_from_probe_and_static(tm):
    out = {o.id: o for o in assess(tm, probe(), compare(scan(), scan()))}
    assert {k: v.status for k, v in out.items()} == {"R1": "satisfied", "R2": "satisfied", "R3": "satisfied",
                                                     "R4": "not_assessed"}
    assert all("passed (HTTP 404)" in e for e in out["R1"].evidence)
    assert out["R3"].evidence == ["static rule 'boundaryrun.python.auth-dependency-removed' produces nothing in the patched tree"]
    assert out["R4"].threat == "T4" and "enforced elsewhere" in out["R4"].evidence[0]


def test_assess_not_satisfied_when_a_check_fails_or_a_rule_matches(tm):
    out = {o.id: o.status for o in assess(tm, probe(cross_blocked=False), compare(scan(), scan()))}
    assert out["R1"] == "not_satisfied" and out["R2"] == "satisfied"
    out = {o.id: o.status for o in assess(tm, probe(legit_ok=False), compare(scan(), scan()))}
    assert out["R2"] == "not_satisfied" and out["R1"] == "satisfied"
    bad = compare(scan(), scan("boundaryrun.python.auth-dependency-removed"))
    out = {o.id: o for o in assess(tm, probe(), bad)}
    assert out["R3"].status == "not_satisfied" and "still matches" in out["R3"].evidence[0]


def test_assess_no_evidence_when_a_check_is_missing_or_a_scan_failed(tm):
    out = {o.id: o for o in assess(tm, probe(omit={"cross_tenant:bob->doc2"}), compare(scan(), scan()))}
    assert out["R1"].status == "no_evidence" and any("absent from results" in e for e in out["R1"].evidence)
    inconclusive = compare(scan(), StaticScan(status="timeout"))
    out = {o.id: o.status for o in assess(tm, probe(), inconclusive)}
    assert out["R3"] == "no_evidence" and out["R1"] == "satisfied"
    failed_probe = ProbeRun(ok=False, error="boom", duration_s=0)
    out = {o.id: o.status for o in assess(tm, failed_probe, compare(scan(), scan()))}
    assert out["R1"] == "no_evidence" and out["R3"] == "satisfied"


def test_assess_marks_everything_not_assessed_without_post_patch_results(tm):
    assert {o.status for o in assess(tm, None, None)} == {"not_assessed"}
    assert all(o.evidence for o in assess(tm, None, None))


def test_verdict_downgrades_on_requirements(tm):
    ok = (verdict_probe(True), suite(), PatchInfo(files=[FileChange(path="app/main.py", change="modified",
                                                                    in_write_scope=True)], diff="x"),
          verdict_probe(False), suite())
    good = assess(tm, probe(), compare(scan(), scan()))
    v = decide(*ok, compare(scan(), scan()), good)
    assert v.status == Status.VERIFIED and any("requirements satisfied: ['R1', 'R2', 'R3']" in r for r in v.reasons)
    unmet = assess(tm, probe(), compare(scan(), scan("boundaryrun.python.auth-dependency-removed")))
    v = decide(*ok, compare(scan(), scan()), unmet)
    assert v.status == Status.NEEDS_REVIEW and any("not satisfied" in r and "R3" in r for r in v.reasons)
    missing = assess(tm, probe(omit={"legit:bob->doc3"}), compare(scan(), scan()))
    v = decide(*ok, compare(scan(), scan()), missing)
    assert v.status == Status.INCONCLUSIVE and any("without evidence" in r and "R2" in r for r in v.reasons)
    # a failed remediation is reported as such before requirements are consulted
    assert decide(verdict_probe(True), suite(), ok[2], verdict_probe(True), suite(), None, unmet).status == Status.NOT_REMEDIATED
