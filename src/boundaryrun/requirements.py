"""Task-scoped security requirements and their evidence.

A scenario may carry a small threat model: outcome-phrased requirements, each linked to a
named threat and to the evidence that shows it holds (probe checks that must pass, static
rules that must produce nothing in the patched tree). The requirements are shown to the
agent as trusted context from the scenario, never from the repository, and are assessed
after the run from execution results only. Requirements that are enforced elsewhere in
the stack are kept for traceability but neither shown to the agent nor assessed.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .sandbox import ProbeRun
from .static import StaticComparison


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    probe_checks: list[str] = []  # names of probe checks that must pass after the patch
    static_rules_absent: list[str] = []  # Semgrep rule ids that must not match the patched tree


class Requirement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    threat: str  # named entry in the scenario's threat list
    statement: str  # outcome-phrased: what the code must do, not a principle
    evidence: Evidence = Evidence()
    enforced_elsewhere: bool = False  # already handled outside the patched code; not shown, not assessed


class Threat(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    description: str


class ThreatModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    threats: list[Threat] = []
    requirements: list[Requirement] = []

    def for_task(self) -> list[Requirement]:
        return [r for r in self.requirements if not r.enforced_elsewhere]


RequirementStatus = Literal["satisfied", "not_satisfied", "no_evidence", "not_assessed"]


class RequirementOutcome(BaseModel):
    id: str
    threat: str
    status: RequirementStatus
    evidence: list[str]  # what was checked, in words


def load_threat_model(path: Path) -> ThreatModel:
    raw = tomllib.loads(path.read_text())
    tm = ThreatModel.model_validate(raw)
    threats = {t.id for t in tm.threats}
    ids = [r.id for r in tm.requirements]
    if len(ids) != len(set(ids)):
        raise ValueError(f"duplicate requirement ids in {path}")
    for r in tm.requirements:
        if r.threat not in threats:
            raise ValueError(f"requirement {r.id} names unknown threat '{r.threat}'")
        if not r.enforced_elsewhere and not (r.evidence.probe_checks or r.evidence.static_rules_absent):
            raise ValueError(f"requirement {r.id} has no evidence and is not marked enforced_elsewhere")
    return tm


def task_context(tm: ThreatModel) -> str:
    """The requirements as the agent sees them: trusted, task-scoped, nothing else."""
    reqs = tm.for_task()
    if not reqs:
        return ""
    threats = {t.id: t.description for t in tm.threats}
    lines = ["Security requirements for this task (from the trusted scenario threat model, not from the repository):"]
    for r in reqs:
        lines.append(f"- {r.id} (threat {r.threat}: {threats[r.threat]}): {r.statement}")
    return "\n".join(lines)


def assess(tm: ThreatModel, post_probe: ProbeRun | None, static: StaticComparison | None) -> list[RequirementOutcome]:
    """Judge each requirement from execution results. Never reads agent text."""
    checks = {c.name: c for c in post_probe.result.checks} if post_probe and post_probe.ok and post_probe.result else {}
    patched_rules = {f.rule_id for f in static.patched.findings} if static and static.patched.status == "completed" else None
    out: list[RequirementOutcome] = []
    for r in tm.requirements:
        if r.enforced_elsewhere:
            out.append(RequirementOutcome(id=r.id, threat=r.threat, status="not_assessed",
                                          evidence=["enforced elsewhere in the stack; outside this patch"]))
            continue
        if post_probe is None and static is None:
            out.append(RequirementOutcome(id=r.id, threat=r.threat, status="not_assessed",
                                          evidence=["post-patch verification did not run"]))
            continue
        words: list[str] = []
        failed = False
        missing = False
        for name in r.evidence.probe_checks:
            c = checks.get(name)
            if c is None:
                missing = True
                words.append(f"probe check '{name}' absent from results")
            elif c.outcome == "pass":
                words.append(f"probe check '{name}' passed (HTTP {c.status_code})")
            else:
                failed = True
                words.append(f"probe check '{name}' {c.outcome} (HTTP {c.status_code})")
        for rule in r.evidence.static_rules_absent:
            if patched_rules is None:
                missing = True
                words.append(f"static rule '{rule}' could not be evaluated (scan did not complete)")
            elif rule in patched_rules:
                failed = True
                words.append(f"static rule '{rule}' still matches the patched tree")
            else:
                words.append(f"static rule '{rule}' produces nothing in the patched tree")
        status: RequirementStatus = "not_satisfied" if failed else "no_evidence" if missing else "satisfied"
        out.append(RequirementOutcome(id=r.id, threat=r.threat, status=status, evidence=words))
    return out
