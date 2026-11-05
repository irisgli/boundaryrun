"""Static analysis with Semgrep, run inside the sandbox on both snapshots.

Rules live in the repository (`rules/`) and are mounted read-only; nothing is fetched.
Findings are compared between the pristine snapshot and the patched workspace so the
verifier can see what a patch resolved and, more importantly, what it introduced.
Findings are matched by rule, file and matched source text, not by line number, so a
patch that only shifts code does not create spurious "new" findings.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


class StaticFinding(BaseModel):
    model_config = ConfigDict(frozen=True)
    rule_id: str
    severity: str
    path: str
    line: int
    message: str
    snippet: str
    cwe: str | None = None

    def identity(self) -> tuple[str, str, str]:
        return (self.rule_id, self.path, " ".join(self.snippet.split()))


class StaticScan(BaseModel):
    status: Literal["completed", "error", "timeout", "not_run"]
    semgrep_version: str | None = None
    rules_sha256: str | None = None
    findings: list[StaticFinding] = []
    parse_errors: int = 0
    error: str | None = None
    duration_s: float = 0.0


class StaticComparison(BaseModel):
    baseline: StaticScan
    patched: StaticScan
    resolved: list[StaticFinding]  # present before, absent after
    introduced: list[StaticFinding]  # absent before, present after
    unchanged: int
    conclusive: bool  # both scans completed


def parse_semgrep_json(raw: str, source_root: Path | None = None) -> tuple[list[StaticFinding], int, str | None]:
    """Parse `semgrep --json`. The matched text is read from `source_root` using the
    reported line range, because the CLI replaces `extra.lines` with "requires login"."""
    data = json.loads(raw)
    findings = []
    cache: dict[str, list[str]] = {}
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        path = r["path"].removeprefix("/work/")
        start, end = r["start"]["line"], r["end"]["line"]
        snippet = ""
        if source_root is not None and (source_root / path).is_file():
            lines = cache.setdefault(path, (source_root / path).read_text("utf-8", "replace").splitlines())
            snippet = "\n".join(lines[start - 1 : end])
        findings.append(
            StaticFinding(
                rule_id=r["check_id"].removeprefix("rules."),  # semgrep prefixes the config directory name
                severity=extra.get("severity", "UNKNOWN"),
                path=path,
                line=start,
                message=extra.get("message", "").strip(),
                snippet=snippet[:400],
                cwe=meta.get("cwe") if isinstance(meta.get("cwe"), str) else None,
            )
        )
    findings.sort(key=lambda f: (f.path, f.line, f.rule_id))
    return findings, len(data.get("errors", [])), data.get("version")


def compare(baseline: StaticScan, patched: StaticScan) -> StaticComparison:
    conclusive = baseline.status == "completed" and patched.status == "completed"
    before = {f.identity(): f for f in baseline.findings}
    after = {f.identity(): f for f in patched.findings}
    return StaticComparison(
        baseline=baseline,
        patched=patched,
        resolved=[f for k, f in before.items() if k not in after] if conclusive else [],
        introduced=[f for k, f in after.items() if k not in before] if conclusive else [],
        unchanged=len(before.keys() & after.keys()) if conclusive else 0,
        conclusive=conclusive,
    )
