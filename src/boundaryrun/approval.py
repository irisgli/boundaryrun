"""Human approval records for a finished investigation.

The gateway allows or denies; it never escalates. The one place a human decision enters
the pipeline is here, after the run, as a record bound to the exact report it approves:
the approval carries the SHA-256 of `report.json`, the verdict it was given, the reviewer
and the decision. A rewritten report orphans its approval. With an operator key present
the record is also HMAC-signed, so a forged approval needs the key, not just write access
to the run directory. `propose` requires an approval for any run whose verdict is not
`verified`, and refuses any run that carries a rejection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .evidence import operator_key, sign

FILENAME = "approval.json"


class Approval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    investigation_id: str
    report_sha256: str
    verdict: str
    decision: Literal["approve", "reject"]
    reviewer: str
    note: str = ""
    recorded_at: str
    hmac: str | None = None  # over the record without this field, under the operator key


class ApprovalError(RuntimeError):
    pass


def _unsigned_bytes(a: Approval) -> bytes:
    body = a.model_dump(exclude={"hmac"})
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def record_approval(run_dir: Path, *, reviewer: str, decision: Literal["approve", "reject"], note: str = "") -> Approval:
    report_path = run_dir / "report.json"
    if not report_path.is_file():
        raise ApprovalError(f"{run_dir} has no report.json")
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    reviewer = reviewer.strip()
    if not reviewer:
        raise ApprovalError("a reviewer name is required; an approval must be attributable")
    a = Approval(
        investigation_id=report["investigation_id"],
        report_sha256=hashlib.sha256(report_bytes).hexdigest(),
        verdict=report["verdict"]["status"],
        decision=decision,
        reviewer=reviewer,
        note=note.strip(),
        recorded_at=datetime.now(UTC).isoformat(),
    )
    if (key := operator_key()) is not None:
        a.hmac = sign(_unsigned_bytes(a), key)
    (run_dir / FILENAME).write_text(a.model_dump_json(indent=2) + "\n")
    return a


class ApprovalCheck(BaseModel):
    approval: Approval | None
    bound: bool | None  # report hash matches; None when there is no approval
    signature: bool | None  # True valid, False invalid or required-but-missing, None not checkable
    problem: str | None


def check_approval(run_dir: Path) -> ApprovalCheck:
    path = run_dir / FILENAME
    if not path.is_file():
        return ApprovalCheck(approval=None, bound=None, signature=None, problem=None)
    try:
        a = Approval.model_validate_json(path.read_text("utf-8"))
    except ValueError as e:
        return ApprovalCheck(approval=None, bound=False, signature=None, problem=f"approval.json invalid: {e}")
    report_path = run_dir / "report.json"
    actual = hashlib.sha256(report_path.read_bytes()).hexdigest() if report_path.is_file() else None
    bound = actual == a.report_sha256
    problem = None if bound else "approval is bound to a different report.json than the one on disk"
    key = operator_key()
    if key is not None:
        if a.hmac is None:
            signature, problem = False, problem or "operator key is set but the approval is unsigned"
        else:
            signature = hmac.compare_digest(a.hmac, sign(_unsigned_bytes(a), key))
            problem = problem or (None if signature else "approval signature does not match the operator key")
    else:
        signature = None
    return ApprovalCheck(approval=a, bound=bound, signature=signature, problem=problem)
