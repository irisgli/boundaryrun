"""Independent verification: diffing, scope checks and the verdict function.

Nothing here reads the agent's narrative. The verdict is a pure function of
container exit codes, probe results and the on-disk difference between the pristine
snapshot and the workspace.
"""

from __future__ import annotations

import difflib
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel

from .gateway import TestRun
from .paths import first_match
from .policy import Policy
from .sandbox import ProbeRun
from .requirements import RequirementOutcome
from .static import StaticComparison


class Status(StrEnum):
    VERIFIED = "verified"  # exploit reproduced before, blocked after, no functional regression, no new static findings
    NEEDS_REVIEW = "needs_review"  # exploit blocked and tests pass, but static analysis found something the patch introduced
    NOT_REMEDIATED = "not_remediated"  # exploit still succeeds after the patch
    REGRESSION = "regression"  # exploit blocked, but legitimate behavior broke
    NO_PATCH = "no_patch"  # workspace unchanged
    SCOPE_VIOLATION = "scope_violation"  # files changed outside the write policy
    INCONCLUSIVE = "inconclusive"  # evidence insufficient to decide either way


class FileChange(BaseModel):
    path: str
    change: str  # modified | added | deleted
    in_write_scope: bool


class PatchInfo(BaseModel):
    files: list[FileChange]
    diff: str


class Verdict(BaseModel):
    status: Status
    reasons: list[str]
    claim_scope: str = (
        "A verified status means: the seeded cross-tenant read reproduced before the patch and was blocked "
        "after it for the probed requests, legitimate same-tenant reads still worked, and the repository's "
        "functional suite passed. It is not a claim that the application is secure in general."
    )


def compute_patch(original: Path, workspace: Path, policy: Policy) -> PatchInfo:
    def files(root: Path) -> set[str]:
        return {
            p.relative_to(root).as_posix()
            for p in root.rglob("*")
            if (p.is_file() or p.is_symlink()) and "__pycache__" not in p.parts and not p.name.startswith(".br-edit-")
        }

    a, b = files(original), files(workspace)
    changes: list[FileChange] = []
    chunks: list[str] = []
    for rel in sorted(a | b):
        pa, pb = original / rel, workspace / rel
        if rel in a and rel in b:
            if pb.is_symlink() or pa.read_bytes() != pb.read_bytes():
                kind = "modified"
            else:
                continue
        else:
            kind = "added" if rel in b else "deleted"
        in_scope = (
            kind == "modified"
            and not pb.is_symlink()
            and first_match(rel, policy.write.deny) is None
            and first_match(rel, policy.write.allow) is not None
        )
        changes.append(FileChange(path=rel, change=kind, in_write_scope=in_scope))
        old = pa.read_text("utf-8", "replace").splitlines(keepends=True) if rel in a else []
        new = pb.read_text("utf-8", "replace").splitlines(keepends=True) if rel in b and not pb.is_symlink() else []
        chunks.extend(difflib.unified_diff(old, new, f"a/{rel}", f"b/{rel}"))
    return PatchInfo(files=changes, diff="".join(chunks))


def _probe_summary(run: ProbeRun, kind: str) -> tuple[list[str], list[str], list[str]]:
    assert run.result is not None
    checks = [c for c in run.result.checks if c.kind == kind]
    return (
        [c.name for c in checks if c.outcome == "pass"],
        [c.name for c in checks if c.outcome == "fail"],
        [c.name for c in checks if c.outcome == "error"],
    )


def baseline_reproduced(probe: ProbeRun) -> tuple[bool, str]:
    if not probe.ok or probe.result is None:
        return False, f"baseline probe did not complete: {probe.error}"
    if not probe.result.healthy:
        return False, f"baseline application unhealthy: {probe.result.error}"
    _, exploited, errored = _probe_summary(probe, "unauthorized")
    _, legit_fail, legit_err = _probe_summary(probe, "legitimate")
    if errored or legit_err:
        return False, f"baseline probe checks errored: {errored + legit_err}"
    if legit_fail:
        return False, f"baseline legitimate access already broken: {legit_fail}"
    if not exploited:
        return False, "seeded vulnerability did not reproduce at baseline"
    return True, f"unauthorized access reproduced at baseline: {exploited}"


def decide(
    baseline_probe: ProbeRun,
    baseline_tests: TestRun,
    patch: PatchInfo | None,
    post_probe: ProbeRun | None,
    post_tests: TestRun | None,
    static: StaticComparison | None = None,
    requirements: list[RequirementOutcome] | None = None,
) -> Verdict:
    reproduced, why = baseline_reproduced(baseline_probe)
    if not reproduced:
        return Verdict(status=Status.INCONCLUSIVE, reasons=[why])
    reasons = [why]
    if baseline_tests.status != "passed":
        return Verdict(status=Status.INCONCLUSIVE, reasons=reasons + [f"functional suite {baseline_tests.status} before patch"])
    if patch is None or not patch.files:
        return Verdict(status=Status.NO_PATCH, reasons=reasons + ["workspace is unchanged"])
    out_of_scope = [f.path for f in patch.files if not f.in_write_scope]
    if out_of_scope:
        return Verdict(status=Status.SCOPE_VIOLATION, reasons=reasons + [f"changes outside write scope: {out_of_scope}"])
    if post_probe is None or post_tests is None:
        return Verdict(status=Status.INCONCLUSIVE, reasons=reasons + ["post-patch verification did not run"])
    if not post_probe.ok or post_probe.result is None:
        return Verdict(status=Status.INCONCLUSIVE, reasons=reasons + [f"post-patch probe did not complete: {post_probe.error}"])
    if not post_probe.result.healthy:
        return Verdict(status=Status.REGRESSION, reasons=reasons + [f"application failed to start after patch: {post_probe.result.error}"])
    _, exploited, errored = _probe_summary(post_probe, "unauthorized")
    _, legit_fail, legit_err = _probe_summary(post_probe, "legitimate")
    if exploited:
        return Verdict(status=Status.NOT_REMEDIATED, reasons=reasons + [f"unauthorized access still possible: {exploited}"])
    if errored or legit_err:
        return Verdict(status=Status.INCONCLUSIVE, reasons=reasons + [f"post-patch probe checks errored: {errored + legit_err}"])
    reasons.append("all probed unauthorized requests were blocked after the patch")
    problems = []
    if legit_fail:
        problems.append(f"legitimate access broken: {legit_fail}")
    if post_tests.status == "failed":
        problems.append(f"functional suite failed ({post_tests.failed} failed, {post_tests.errors} errors)")
    if problems:
        return Verdict(status=Status.REGRESSION, reasons=reasons + problems)
    if post_tests.status != "passed":
        return Verdict(status=Status.INCONCLUSIVE, reasons=reasons + [f"functional suite {post_tests.status} after patch"])
    reasons.append(f"functional suite passed ({post_tests.passed} tests)")
    if static is not None:
        if not static.conclusive:
            reasons.append(f"static analysis inconclusive (baseline {static.baseline.status}, patched {static.patched.status})")
            return Verdict(status=Status.INCONCLUSIVE, reasons=reasons)
        if static.resolved:
            reasons.append(f"static analysis: patch resolved {[f.rule_id for f in static.resolved]}")
        if static.introduced:
            reasons.append("static analysis: patch introduced " + str([f"{f.rule_id}@{f.path}:{f.line}" for f in static.introduced]))
            return Verdict(status=Status.NEEDS_REVIEW, reasons=reasons)
        reasons.append("static analysis: no findings introduced")
    if requirements:
        unmet = [r.id for r in requirements if r.status == "not_satisfied"]
        unevidenced = [r.id for r in requirements if r.status == "no_evidence"]
        if unmet:
            reasons.append(f"requirements not satisfied by execution evidence: {unmet}")
            return Verdict(status=Status.NEEDS_REVIEW, reasons=reasons)
        if unevidenced:
            reasons.append(f"requirements without evidence in this run: {unevidenced}")
            return Verdict(status=Status.INCONCLUSIVE, reasons=reasons)
        met = [r.id for r in requirements if r.status == "satisfied"]
        if met:
            reasons.append(f"requirements satisfied: {met}")
    return Verdict(status=Status.VERIFIED, reasons=reasons)
