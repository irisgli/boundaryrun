"""Verdict function and patch scoping, with synthetic evidence (no Docker)."""

import pytest

from boundaryrun.gateway import TestRun
from boundaryrun.sandbox import ProbeCheck, ProbeResult, ProbeRun
from boundaryrun.verify import FileChange, PatchInfo, Status, compute_patch, decide


def probe(exploitable: bool, legit_ok: bool = True, healthy: bool = True, err: bool = False) -> ProbeRun:
    checks = [
        ProbeCheck(name="cross", kind="unauthorized", status_code=200 if exploitable else 404,
                   content_returned=exploitable, outcome="error" if err else ("fail" if exploitable else "pass")),
        ProbeCheck(name="legit", kind="legitimate", status_code=200 if legit_ok else 404,
                   content_returned=legit_ok, outcome="pass" if legit_ok else "fail"),
    ]
    return ProbeRun(ok=True, result=ProbeResult(healthy=healthy, error=None if healthy else "down",
                                                checks=checks if healthy else []), duration_s=1)


def suite(status="passed", failed=0) -> TestRun:
    return TestRun(exit_code={"passed": 0, "failed": 1}.get(status), status=status, passed=7 - failed,
                   failed=failed, duration_s=1)


PATCH = PatchInfo(files=[FileChange(path="app/main.py", change="modified", in_write_scope=True)], diff="x")


@pytest.mark.parametrize(
    "args,status",
    [
        ((probe(True), suite(), PATCH, probe(False), suite()), Status.VERIFIED),
        ((probe(True), suite(), PATCH, probe(True), suite()), Status.NOT_REMEDIATED),
        ((probe(True), suite(), PATCH, probe(False, legit_ok=False), suite()), Status.REGRESSION),
        ((probe(True), suite(), PATCH, probe(False), suite("failed", 2)), Status.REGRESSION),
        ((probe(True), suite(), PATCH, probe(False, healthy=False), suite()), Status.REGRESSION),
        ((probe(True), suite(), PATCH, probe(False), suite("timeout")), Status.INCONCLUSIVE),
        ((probe(True), suite(), PATCH, probe(False), suite("error")), Status.INCONCLUSIVE),
        ((probe(True), suite(), PATCH, probe(False, err=True), suite()), Status.INCONCLUSIVE),
        ((probe(True), suite(), PATCH, ProbeRun(ok=False, error="boom", duration_s=0), suite()), Status.INCONCLUSIVE),
        ((probe(True), suite(), PATCH, None, None), Status.INCONCLUSIVE),
        ((probe(True), suite(), PatchInfo(files=[], diff=""), None, None), Status.NO_PATCH),
        ((probe(True), suite(), None, None, None), Status.NO_PATCH),
        ((probe(False), suite(), PATCH, probe(False), suite()), Status.INCONCLUSIVE),
        ((probe(True, legit_ok=False), suite(), PATCH, probe(False), suite()), Status.INCONCLUSIVE),
        ((probe(True), suite("failed", 1), PATCH, probe(False), suite()), Status.INCONCLUSIVE),
        ((ProbeRun(ok=False, error="x", duration_s=0), suite(), PATCH, probe(False), suite()), Status.INCONCLUSIVE),
        ((probe(True), suite(),
          PatchInfo(files=[FileChange(path="tests/t.py", change="modified", in_write_scope=False)], diff="x"),
          probe(False), suite()), Status.SCOPE_VIOLATION),
    ],
)
def test_decide(args, status):
    v = decide(*args)
    assert v.status == status, v.reasons
    assert v.reasons


def test_unremediated_takes_precedence_over_regression():
    v = decide(probe(True), suite(), PATCH, probe(True, legit_ok=False), suite("failed", 3))
    assert v.status == Status.NOT_REMEDIATED


def test_compute_patch_flags_added_deleted_and_out_of_scope(tmp_path, scenario):
    import shutil

    a, b = tmp_path / "a", tmp_path / "b"
    shutil.copytree(scenario.target, a, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(a, b)
    (b / "app" / "main.py").write_text((b / "app" / "main.py").read_text() + "\n# x\n")
    (b / "app" / "new.py").write_text("x = 1\n")
    (b / "tests" / "test_functional.py").write_text("")
    (b / "app" / "store.py").unlink()
    info = compute_patch(a, b, scenario.policy)
    got = {f.path: (f.change, f.in_write_scope) for f in info.files}
    assert got == {
        "app/main.py": ("modified", True),
        "app/new.py": ("added", False),
        "app/store.py": ("deleted", False),
        "tests/test_functional.py": ("modified", False),
    }
    assert "+# x" in info.diff


def test_compute_patch_no_changes(tmp_path, scenario):
    import shutil

    a = tmp_path / "a"
    shutil.copytree(scenario.target, a, ignore=shutil.ignore_patterns("__pycache__"))
    assert compute_patch(a, a, scenario.policy).files == []
