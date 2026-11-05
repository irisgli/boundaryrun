"""Controlled pull-request proposal from a finished investigation.

Turning a patch into a PR is a separate, explicit step with four gates:

1. Release eligibility. A `verified` verdict releases on its own. A `needs_review` verdict
   releases only with a human approval bound to this exact report (see approval.py). Any
   other verdict, any planted attack, any rejection, and (by default) any simulated run is
   refused.
2. The patch is re-applied with `git apply` to a fresh clone at the recorded commit and
   must produce exactly the files the report lists; the resulting tree is re-diffed and
   must match the report's diff hash.
3. Identity. The commit is authored by the agent identity, never by the operator, and
   carries trailers that tie it to the investigation, the verdict, the audit chain head,
   the report hash and the approver. The operator, if named, is a co-author.
4. Credentials. git and gh run with a minimal environment. A push to an https remote
   requires a dedicated agent token in `BOUNDARYRUN_AGENT_TOKEN`; the operator's ambient
   credentials (keychain, ssh agent, gh login) are never used. ssh remotes are refused for
   that reason. Local and file:// remotes need no credential.

Pushing and opening the PR each require their own flag. Nothing is ever merged. The PR
body is generated from the evidence report, not from agent text, and the agent's own
summary is quoted as a claim.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from .approval import Approval, check_approval
from .pipeline import Report
from .repo import MINIMAL_ENV, RepoError, _git
from .verify import Status

AGENT_NAME = "BoundaryRun Agent"
AGENT_EMAIL = "agent@boundaryrun.invalid"
TOKEN_ENV = "BOUNDARYRUN_AGENT_TOKEN"
BRANCH_PREFIX = "boundaryrun/"

CredentialSource = Literal["none_local_remote", "agent_token"]


class ProposalError(RuntimeError):
    pass


class Proposal(BaseModel):
    investigation_id: str
    branch: str
    base_commit: str
    commit: str | None = None
    pushed: bool = False
    pr_url: str | None = None
    body_path: str
    identity: str = f"{AGENT_NAME} <{AGENT_EMAIL}>"
    co_author: str | None = None
    credential_source: CredentialSource = "none_local_remote"
    approval: dict | None = None  # reviewer, decision, recorded_at
    trailers: dict[str, str] = {}


def _require_releasable(report: Report, approval: Approval | None, allow_simulated: bool) -> None:
    status = report.verdict.status
    if approval is not None and approval.decision == "reject":
        raise ProposalError(f"refusing to propose: run was rejected by {approval.reviewer}")
    if status == Status.NEEDS_REVIEW:
        if approval is None:
            raise ProposalError("refusing to propose: verdict is 'needs_review' and no human approval is recorded "
                                "(use `boundaryrun approve`)")
    elif status != Status.VERIFIED:
        raise ProposalError(f"refusing to propose: verdict is '{status.value}', not 'verified'")
    if report.patch is None or not report.patch.diff:
        raise ProposalError("refusing to propose: report has no patch")
    if report.attack is not None:
        raise ProposalError("refusing to propose: run had a planted attack (evaluation run, not a remediation)")
    if (report.agent is None or report.agent.mode != "live") and not allow_simulated:
        raise ProposalError("refusing to propose: patch did not come from a live agent run (use --allow-simulated for tests)")


def classify_remote(remote: str) -> Literal["local", "https", "ssh", "other"]:
    r = remote.strip()
    if r.startswith(("https://", "http://")):
        return "https"
    if r.startswith(("ssh://", "git@")) or ("@" in r.split("/")[0] and ":" in r.split("/")[0]):
        return "ssh"
    if r.startswith("file://") or Path(r).exists():
        return "local"
    return "other"


def _credentials(remote: str, needed: bool) -> tuple[CredentialSource, dict[str, str], list[str]]:
    """Return (source, extra env for git and gh, extra git -c args)."""
    kind = classify_remote(remote)
    if kind == "local":
        return "none_local_remote", {}, []
    if kind == "ssh":
        raise ProposalError("refusing ssh remote: pushing would use the operator's ssh identity; use an https remote "
                            f"with {TOKEN_ENV}")
    if kind == "other":
        raise ProposalError(f"unrecognized remote '{remote}'")
    token = os.environ.get(TOKEN_ENV, "")
    if needed and not token:
        raise ProposalError(f"refusing to push with ambient credentials; set {TOKEN_ENV} to a scoped, short-lived token "
                            "for the agent identity")
    if not token:
        return "agent_token", {}, []
    helper = '!f() { echo username=x-access-token; echo "password=$' + TOKEN_ENV + '"; }; f'
    return "agent_token", {TOKEN_ENV: token, "GH_TOKEN": token}, ["-c", "credential.helper=", "-c", f"credential.helper={helper}"]


def render_pr_body(report: Report, approval: Approval | None, identity: str) -> str:
    v = report.verdict
    f = report.finding
    s = report.policy_summary
    b = report.baseline["probe"]["result"]
    p = report.post_patch["probe"]["result"]
    simulated = report.agent is None or report.agent.mode != "live"
    lines = [
        f"## {f.get('title', f.get('id', 'Security finding'))}",
        "",
        *(["**SIMULATED AGENT RUN: the patch comes from a scripted fixture, not an autonomous investigation.**", ""] if simulated else []),
        f"Investigation `{report.investigation_id}` (BoundaryRun {report.execution.boundaryrun_version}).",
        f"Finding `{f.get('id')}`, {f.get('cwe', '')} severity {f.get('severity', '?')}.",
        f"Opened by `{identity}`; audit chain head `{(report.audit_chain_head or '')[:16]}`.",
        "",
        "### Independent verification",
        "",
        f"Verdict: **{v.status.value}**",
        "",
        *[f"- {r}" for r in v.reasons],
        "",
        "| probe check | before | after |",
        "|---|---|---|",
    ]
    after = {c["name"]: c for c in p["checks"]}
    for c in b["checks"]:
        a = after.get(c["name"], {})
        lines.append(f"| {c['name']} ({c['kind']}) | HTTP {c['status_code']}, {c['outcome']} | HTTP {a.get('status_code')}, {a.get('outcome')} |")
    if report.requirements:
        lines += ["", "| requirement | threat | status |", "|---|---|---|"]
        for r in report.requirements:
            lines.append(f"| {r.id} | {r.threat} | {r.status} |")
    if report.static_analysis:
        st = report.static_analysis
        lines += ["", f"Static analysis (semgrep {st.patched.semgrep_version}): "
                      f"{len(st.resolved)} resolved, {len(st.introduced)} introduced, {st.unchanged} unchanged."]
    if approval is not None:
        lines += ["", f"Human approval: **{approval.decision}** by {approval.reviewer} at {approval.recorded_at}"
                      + (f" ({approval.note})" if approval.note else "") + ", bound to report "
                      f"`{approval.report_sha256[:16]}`" + (" and signed." if approval.hmac else ".")]
    lines += [
        "",
        "### Agent operations",
        "",
        f"{s.requests} tool requests: {s.executed} executed, {s.denied} denied, {s.rejected} rejected.",
    ]
    if report.claim_check is not None:
        cc = report.claim_check
        lines.append(f"Agent's claimed files {cc.files_claimed} {'match' if cc.consistent else 'DO NOT match'} "
                     f"the diff {cc.files_changed}.")
    lines += [
        "",
        "### Agent's own summary (unverified claim)",
        "",
        f"> {report.agent_claim.summary if report.agent_claim else '(none)'}",
        "",
        f"Model: `{', '.join(report.agent.models_observed) if report.agent else 'n/a'}`. "
        f"Evidence report hash: `{hashlib.sha256(report.model_dump_json().encode()).hexdigest()[:16]}`.",
        "",
        "This pull request was generated by BoundaryRun. It is a proposal for human review and was not merged automatically.",
    ]
    return "\n".join(lines) + "\n"


def propose(run_dir: Path, *, remote: str, base_branch: str, push: bool = False, open_pr: bool = False,
            gh: str = "gh", allow_simulated: bool = False, operator: str | None = None) -> Proposal:
    report_path = run_dir / "report.json"
    report_bytes = report_path.read_bytes()
    report = Report.model_validate(json.loads(report_bytes))
    ac = check_approval(run_dir)
    if ac.problem:
        raise ProposalError(f"refusing to propose: {ac.problem}")
    _require_releasable(report, ac.approval, allow_simulated)
    repo_source = report.task.get("repo")
    if not repo_source:
        raise ProposalError("refusing to propose: investigation did not come from a git repository (no pinned commit)")
    base_commit = repo_source["commit"]
    diff_path = run_dir / "patch.diff"
    if hashlib.sha256(diff_path.read_bytes()).hexdigest() != report.artifacts.get("patch.diff"):
        raise ProposalError("patch.diff does not match the hash recorded in the report")
    if open_pr and not push:
        raise ProposalError("--open-pr requires --push")
    source, extra_env, cred_args = _credentials(remote, needed=push)

    clone = run_dir / "proposal"
    if clone.exists():
        shutil.rmtree(clone)
    try:
        _git([*cred_args, "clone", "--quiet", remote, str(clone)], env=extra_env)
        _git(["checkout", "--quiet", "--detach", base_commit], cwd=clone)
    except RepoError as e:
        raise ProposalError(str(e)) from None
    branch = f"{BRANCH_PREFIX}{report.investigation_id}"
    _git(["checkout", "--quiet", "-b", branch], cwd=clone)
    subdir = repo_source.get("subdir") or ""
    try:
        _git(["apply", "--check", f"--directory={subdir}" if subdir else "--index", str(diff_path)], cwd=clone)
        _git(["apply", "--index", *([f"--directory={subdir}"] if subdir else []), str(diff_path)], cwd=clone)
    except RepoError as e:
        raise ProposalError(f"patch does not apply cleanly at {base_commit[:12]}: {e}") from None
    changed = _git(["diff", "--cached", "--name-only"], cwd=clone).splitlines()
    expected = sorted((f"{subdir}/" if subdir else "") + f.path for f in report.patch.files)
    if sorted(changed) != expected:
        raise ProposalError(f"applied patch touched {changed}, report lists {expected}")

    identity = f"{AGENT_NAME} <{AGENT_EMAIL}>"
    body = render_pr_body(report, ac.approval, identity)
    body_path = run_dir / "pr_body.md"
    body_path.write_text(body)
    title = f"fix: {report.finding.get('title', report.finding.get('id', 'security finding'))}"[:72]
    trailers = {
        "Investigation": report.investigation_id,
        "Verdict": report.verdict.status.value,
        "Audit-Chain-Head": report.audit_chain_head or "none",
        "Report-SHA256": hashlib.sha256(report_bytes).hexdigest(),
        "Agent-Mode": report.agent.mode if report.agent else "none",
    }
    if ac.approval is not None:
        trailers["Approved-by"] = ac.approval.reviewer
    if operator:
        trailers["Co-authored-by"] = operator.strip()
    message = f"{title}\n\nProposed by {identity} from a BoundaryRun investigation.\n\n" + \
        "\n".join(f"{k}: {v}" for k, v in trailers.items())
    _git(["-c", f"user.name={AGENT_NAME}", "-c", f"user.email={AGENT_EMAIL}", "commit", "--quiet", "--no-gpg-sign",
          "-m", message], cwd=clone,
         env={"GIT_AUTHOR_NAME": AGENT_NAME, "GIT_AUTHOR_EMAIL": AGENT_EMAIL,
              "GIT_COMMITTER_NAME": AGENT_NAME, "GIT_COMMITTER_EMAIL": AGENT_EMAIL})
    commit = _git(["rev-parse", "HEAD"], cwd=clone)
    proposal = Proposal(
        investigation_id=report.investigation_id, branch=branch, base_commit=base_commit, commit=commit,
        body_path=str(body_path), identity=identity, co_author=operator.strip() if operator else None,
        credential_source=source, trailers=trailers,
        approval=({"reviewer": ac.approval.reviewer, "decision": ac.approval.decision,
                   "recorded_at": ac.approval.recorded_at} if ac.approval else None),
    )
    if push:
        _git([*cred_args, "push", "--quiet", "origin", f"{branch}:{branch}"], cwd=clone, env=extra_env)
        proposal.pushed = True
    if open_pr:
        r = subprocess.run([gh, "pr", "create", "--base", base_branch, "--head", branch, "--title", title,
                            "--body-file", str(body_path)], cwd=clone, capture_output=True, text=True, check=False,
                           env={**MINIMAL_ENV, **extra_env})
        if r.returncode != 0:
            raise ProposalError(f"gh pr create failed: {r.stderr.strip()[:300]}")
        proposal.pr_url = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else None
    (run_dir / "proposal.json").write_text(proposal.model_dump_json(indent=2))
    return proposal
