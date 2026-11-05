"""Tamper evidence for a finished investigation.

The audit log is a hash chain: every record carries the hash of the previous record
and its own hash over its serialized text, so a record cannot be altered, removed or
inserted without changing every hash after it. The report stores the chain head and
the SHA-256 of each artifact. `verify_run` recomputes all of it from the files on
disk and, when an operator key is present, checks the HMAC written at run time.

The hash is defined over text, not over an object model, so that any language can
verify it: hash_n = sha256(hash_{n-1} || text_n) where text_n is the record's JSON
line with the trailing `,"record_hash":"..."` member removed and hash_0 is 64 zeros.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel

GENESIS = "0" * 64
KEY_ENV = "BOUNDARYRUN_AUDIT_KEY"
_HASH_SUFFIX = re.compile(r',"record_hash":"([0-9a-f]{64})"\}$')


def _text(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "record_hash"}
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False)


def chain_records(records: list[dict[str, Any]]) -> tuple[list[str], str]:
    """Return the JSONL lines (without newlines) and the chain head.

    Each input record is mutated to carry `prev_hash` and `record_hash`.
    """
    prev = GENESIS
    lines: list[str] = []
    for rec in records:
        rec.pop("record_hash", None)
        rec["prev_hash"] = prev
        text = _text(rec)
        digest = hashlib.sha256((prev + text).encode("utf-8")).hexdigest()
        rec["record_hash"] = digest
        lines.append(text[:-1] + f',"record_hash":"{digest}"}}')
        prev = digest
    return lines, prev


def verify_chain(lines: list[str]) -> tuple[bool, str, str | None]:
    """Recompute the chain over raw JSONL lines. Returns (ok, head, first problem)."""
    prev = GENESIS
    for n, line in enumerate(lines, 1):
        m = _HASH_SUFFIX.search(line)
        if not m:
            return False, prev, f"record {n} has no record_hash"
        text = line[: m.start()] + "}"
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return False, prev, f"record {n} is not valid JSON"
        if rec.get("prev_hash") != prev:
            return False, prev, f"record {n} prev_hash does not match the previous record"
        if rec.get("seq") != n:
            return False, prev, f"record {n} has seq {rec.get('seq')}"
        expected = hashlib.sha256((prev + text).encode("utf-8")).hexdigest()
        if m.group(1) != expected:
            return False, prev, f"record {n} hash mismatch"
        prev = expected
    return True, prev, None


def sign(data: bytes, key: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def operator_key() -> bytes | None:
    k = os.environ.get(KEY_ENV)
    return k.encode("utf-8") if k else None


class Check(BaseModel):
    name: str
    ok: bool | None  # None: could not be checked here
    detail: str


class Verification(BaseModel):
    run_dir: str
    investigation_id: str | None
    checks: list[Check]

    @property
    def ok(self) -> bool:
        return all(c.ok is not False for c in self.checks)


def verify_run(run_dir: Path) -> Verification:
    run_dir = run_dir.resolve()
    checks: list[Check] = []
    report_path = run_dir / "report.json"
    try:
        report_bytes = report_path.read_bytes()
        report = json.loads(report_bytes)
    except (OSError, json.JSONDecodeError) as e:
        return Verification(run_dir=str(run_dir), investigation_id=None,
                            checks=[Check(name="report", ok=False, detail=f"report.json unreadable: {e}")])
    inv_id = report.get("investigation_id")
    artifacts: dict[str, str] = report.get("artifacts") or {}

    for name, digest in sorted(artifacts.items()):
        p = run_dir / name
        if not p.is_file():
            checks.append(Check(name=f"artifact {name}", ok=False, detail="file missing"))
            continue
        actual = hashlib.sha256(p.read_bytes()).hexdigest()
        checks.append(Check(name=f"artifact {name}", ok=actual == digest,
                            detail="sha256 matches report" if actual == digest else f"sha256 {actual[:12]} != report {digest[:12]}"))

    audit_path = run_dir / "audit.jsonl"
    lines = [ln for ln in audit_path.read_text("utf-8").split("\n") if ln] if audit_path.is_file() else []
    if not audit_path.is_file():
        checks.append(Check(name="audit chain", ok=False, detail="audit.jsonl missing"))
    elif (claimed := report.get("audit_chain_head")) is None:
        checks.append(Check(name="audit chain", ok=None,
                            detail="report predates audit chaining; only the file hash can be checked"))
    else:
        ok, head, problem = verify_chain(lines)
        checks.append(Check(name="audit chain", ok=ok, detail=problem or f"{len(lines)} records, head {head[:12]}"))
        checks.append(Check(name="chain head in report", ok=claimed == head,
                            detail="matches" if claimed == head else f"report says {claimed[:12]}, log ends at {head[:12]}"))
        in_report = [r.get("record_hash") for r in report.get("tool_requests") or []]
        in_log = []
        for ln in lines:
            m = _HASH_SUFFIX.search(ln)
            in_log.append(m.group(1) if m else None)
        same = in_report == in_log
        checks.append(Check(name="report tool_requests vs audit.jsonl", ok=same,
                            detail="same records in the same order" if same else f"{len(in_report)} in report, {len(in_log)} in log, or hashes differ"))

    patch = report.get("patch") or {}
    diff_path = run_dir / "patch.diff"
    if patch.get("diff"):
        if diff_path.is_file():
            same = diff_path.read_text("utf-8") == patch["diff"]
            checks.append(Check(name="patch.diff vs report.patch.diff", ok=same,
                                detail="identical" if same else "the diff on disk differs from the one in the report"))
        else:
            checks.append(Check(name="patch.diff vs report.patch.diff", ok=False, detail="patch.diff missing"))

    key = operator_key()
    sig_path = run_dir / "report.hmac"
    if sig_path.is_file() and key is not None:
        expected = sign(report_bytes, key)
        good = hmac.compare_digest(sig_path.read_text("utf-8").strip(), expected)
        checks.append(Check(name="report HMAC", ok=good, detail="valid under the operator key" if good else "signature does not match the operator key"))
    elif sig_path.is_file():
        checks.append(Check(name="report HMAC", ok=None, detail=f"report.hmac present; set {KEY_ENV} to verify it"))
    elif key is not None:
        checks.append(Check(name="report HMAC", ok=False, detail="operator key is set but the run has no report.hmac"))
    else:
        checks.append(Check(name="report HMAC", ok=None, detail=f"not signed (no {KEY_ENV} at run time)"))

    from .approval import check_approval  # local import: approval depends on this module

    ac = check_approval(run_dir)
    if ac.approval is not None or ac.problem:
        who = f"{ac.approval.decision} by {ac.approval.reviewer}" if ac.approval else "unreadable"
        ok = None if ac.bound and ac.signature is None else bool(ac.bound and ac.signature is not False)
        detail = ac.problem or (f"{who}, bound to this report" + (", signed" if ac.signature else ", unsigned"))
        checks.append(Check(name="approval", ok=ok, detail=detail))
    return Verification(run_dir=str(run_dir), investigation_id=inv_id, checks=checks)
