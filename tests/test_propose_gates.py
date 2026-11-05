"""Proposal gates that need no Docker: release eligibility, identity, trailers, credentials.

A run directory is synthesized from a real diff of the docvault fix (so `git apply` and the
file-list comparison are exercised for real) and a report whose verdict, approval and mode
are set per test. The remote is a local bare repository, so no credential is needed.
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from boundaryrun.agent import AgentRun
from boundaryrun.approval import record_approval
from boundaryrun.evidence import KEY_ENV
from boundaryrun.gateway import SubmitRemediation
from boundaryrun.pipeline import ExecutionMeta, InjectionObservation, PolicySummary, Report, load_scenario
from boundaryrun.propose import (
    AGENT_EMAIL,
    AGENT_NAME,
    TOKEN_ENV,
    ProposalError,
    _credentials,
    classify_remote,
    propose,
)
from boundaryrun.repo import MINIMAL_ENV
from boundaryrun.verify import Status, Verdict, compute_patch

from .conftest import ROOT, SCENARIO

FIX = ("    if doc is None:\n", "    if doc is None or doc.tenant_id != user.tenant_id:\n")


def git(*args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture(scope="module")
def remote(tmp_path_factory):
    seed = tmp_path_factory.mktemp("seed")
    shutil.copytree(ROOT / "targets" / "docvault", seed / "docvault", ignore=shutil.ignore_patterns("__pycache__"))
    git("init", "-q", "-b", "main", cwd=seed)
    git("add", "-A", cwd=seed)
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "seed", cwd=seed)
    bare = tmp_path_factory.mktemp("remote") / "repo.git"
    git("clone", "-q", "--bare", str(seed), str(bare), cwd=seed)
    return bare, git("rev-parse", "HEAD", cwd=seed)


def _probe(after: bool) -> dict:
    checks = [{"name": "cross_tenant:bob->doc1", "kind": "unauthorized", "status_code": 404 if after else 200,
               "content_returned": not after, "outcome": "pass" if after else "fail", "error": None},
              {"name": "legit:alice->doc1", "kind": "legitimate", "status_code": 200, "content_returned": True,
               "outcome": "pass", "error": None}]
    return {"ok": True, "result": {"healthy": True, "error": None, "checks": checks}, "duration_s": 1.0, "app_log_tail": ""}


def make_run(tmp_path: Path, remote, *, status: Status = Status.VERIFIED, mode: str = "fixture") -> Path:
    """A run directory with a genuine patch.diff for the docvault fix and a report that validates."""
    bare, head = remote
    policy = load_scenario(SCENARIO).policy
    scn_policy = policy.model_dump()
    original, workspace = tmp_path / "original", tmp_path / "workspace"
    shutil.copytree(ROOT / "targets" / "docvault", original, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(original, workspace)
    main = workspace / "app" / "main.py"
    main.write_text(main.read_text().replace(*FIX))
    patch = compute_patch(original, workspace, policy)
    run = tmp_path / f"inv-20260101T000000Z-{uuid.uuid4().hex[:6]}"
    run.mkdir()
    (run / "patch.diff").write_text(patch.diff)
    (run / "audit.jsonl").write_text("")
    now = datetime.now(UTC).isoformat()
    agent = AgentRun(mode=mode, autonomous=mode == "live", fixture="good" if mode == "fixture" else None,
                     finished_by="submit_remediation", models_observed=["m"] if mode == "live" else [])
    report = Report(
        investigation_id=run.name, scenario_id="docvault-idor", arm="protected",
        task={"agent_mode": mode, "attack": None, "fixture": "good",
              "repo": {"url": str(bare), "ref": "main", "commit": head, "subdir": "docvault"},
              "target": str(original), "model": None, "policy": scn_policy, "sandbox": {}},
        execution=ExecutionMeta(boundaryrun_version="0.1.0", python="3.12", platform="test", docker_server=None,
                                runner_image="boundaryrun-runner:0.1", runner_image_id=None, started_at=now, finished_at=now),
        finding={"id": "DOCVAULT-IDOR-1", "title": "Cross-tenant document read", "cwe": "CWE-639", "severity": "high"},
        agent=agent, agent_skipped_reason=None,
        agent_claim=SubmitRemediation(summary="Return 404 for other tenants.", files_changed=["app/main.py"]),
        tool_requests=[], policy_summary=PolicySummary(requests=0, executed=0, denied=0, rejected=0, errors=0, denied_by_rule={}),
        injection=InjectionObservation(injection_files=[], injection_files_read=[], sensitive_read_attempts=0,
                                       sensitive_read_executed=0, egress_attempts=0, egress_executed=0,
                                       out_of_scope_write_attempts=0, out_of_scope_write_executed=0, canary_hits_by_channel={}),
        attack=None, egress_sink=[],
        baseline={"probe": _probe(False), "functional_tests": {"exit_code": 0, "status": "passed", "passed": 7, "duration_s": 1}},
        patch=patch, post_patch={"probe": _probe(True), "functional_tests": {"exit_code": 0, "status": "passed", "passed": 7, "duration_s": 1}},
        static_analysis=None, errors=[],
        verdict=Verdict(status=status, reasons=["synthetic"]),
        artifacts={"patch.diff": hashlib.sha256((run / "patch.diff").read_bytes()).hexdigest(),
                   "audit.jsonl": hashlib.sha256(b"").hexdigest()},
        audit_chain_head=None,
    )
    (run / "report.json").write_text(report.model_dump_json(indent=2))
    return run


@pytest.fixture(autouse=True)
def _no_operator_key(monkeypatch):
    monkeypatch.delenv(KEY_ENV, raising=False)
    monkeypatch.delenv(TOKEN_ENV, raising=False)


def test_commit_is_authored_by_the_agent_identity_with_trailers(tmp_path, remote):
    bare, head = remote
    run = make_run(tmp_path, remote)
    p = propose(run, remote=str(bare), base_branch="main", push=True, allow_simulated=True,
                operator="Iris Li <iris@example.invalid>")
    assert p.identity == f"{AGENT_NAME} <{AGENT_EMAIL}>" and p.credential_source == "none_local_remote"
    assert p.co_author == "Iris Li <iris@example.invalid>" and p.approval is None
    author, committer = git("log", "-1", "--format=%an <%ae>%n%cn <%ce>", p.commit, cwd=bare).splitlines()
    assert author == committer == f"{AGENT_NAME} <{AGENT_EMAIL}>"
    body = git("log", "-1", "--format=%B", p.commit, cwd=bare)
    report_sha = hashlib.sha256((run / "report.json").read_bytes()).hexdigest()
    for line in (f"Investigation: {run.name}", "Verdict: verified", "Audit-Chain-Head: none", f"Report-SHA256: {report_sha}",
                 "Agent-Mode: fixture", "Co-authored-by: Iris Li <iris@example.invalid>"):
        assert line in body.splitlines(), body
    assert "Approved-by" not in body
    assert git("diff", "--name-only", f"{head}..{p.commit}", cwd=bare) == "docvault/app/main.py"
    assert json.loads((run / "proposal.json").read_text())["trailers"]["Report-SHA256"] == report_sha
    assert f"Opened by `{AGENT_NAME} <{AGENT_EMAIL}>`" in (run / "pr_body.md").read_text()


def test_needs_review_requires_a_bound_approval(tmp_path, remote):
    bare, _ = remote
    run = make_run(tmp_path, remote, status=Status.NEEDS_REVIEW)
    with pytest.raises(ProposalError, match="needs_review.*no human approval"):
        propose(run, remote=str(bare), base_branch="main", allow_simulated=True)
    a = record_approval(run, reviewer="Iris", decision="approve", note="identity is a test fixture")
    p = propose(run, remote=str(bare), base_branch="main", allow_simulated=True)
    assert p.approval == {"reviewer": "Iris", "decision": "approve", "recorded_at": a.recorded_at}
    assert p.trailers["Approved-by"] == "Iris" and p.trailers["Verdict"] == "needs_review"
    body = (run / "pr_body.md").read_text()
    assert "Human approval: **approve** by Iris" in body and "identity is a test fixture" in body
    assert "Approved-by: Iris" in git("log", "-1", "--format=%B", p.commit, cwd=run / "proposal")


def test_approval_bound_to_another_report_is_refused(tmp_path, remote):
    bare, _ = remote
    run = make_run(tmp_path, remote, status=Status.NEEDS_REVIEW)
    record_approval(run, reviewer="Iris", decision="approve")
    report = json.loads((run / "report.json").read_text())
    report["verdict"]["reasons"].append("edited after approval")
    (run / "report.json").write_text(json.dumps(report, indent=2))
    with pytest.raises(ProposalError, match="different report.json"):
        propose(run, remote=str(bare), base_branch="main", allow_simulated=True)


def test_unsigned_approval_is_refused_when_the_operator_key_is_set(tmp_path, remote, monkeypatch):
    bare, _ = remote
    run = make_run(tmp_path, remote, status=Status.NEEDS_REVIEW)
    record_approval(run, reviewer="Iris", decision="approve")
    monkeypatch.setenv(KEY_ENV, "operator-secret")
    with pytest.raises(ProposalError, match="unsigned"):
        propose(run, remote=str(bare), base_branch="main", allow_simulated=True)
    record_approval(run, reviewer="Iris", decision="approve")  # signed under the key
    assert propose(run, remote=str(bare), base_branch="main", allow_simulated=True).approval["reviewer"] == "Iris"


def test_rejection_blocks_even_a_verified_run(tmp_path, remote):
    bare, _ = remote
    run = make_run(tmp_path, remote)
    record_approval(run, reviewer="Iris", decision="reject", note="not this way")
    with pytest.raises(ProposalError, match="rejected by Iris"):
        propose(run, remote=str(bare), base_branch="main", allow_simulated=True)


def test_other_verdicts_are_refused_even_with_an_approval(tmp_path, remote):
    bare, _ = remote
    run = make_run(tmp_path, remote, status=Status.REGRESSION)
    record_approval(run, reviewer="Iris", decision="approve")
    with pytest.raises(ProposalError, match="'regression', not 'verified'"):
        propose(run, remote=str(bare), base_branch="main", allow_simulated=True)


def test_live_run_needs_no_simulated_override(tmp_path, remote):
    bare, _ = remote
    run = make_run(tmp_path, remote, mode="live")
    p = propose(run, remote=str(bare), base_branch="main")
    assert p.trailers["Agent-Mode"] == "live" and "SIMULATED" not in (run / "pr_body.md").read_text()


@pytest.mark.parametrize("remote_url", ["git@github.com:org/repo.git", "ssh://git@github.com/org/repo.git"])
def test_ssh_remotes_are_refused(tmp_path, remote, remote_url):
    assert classify_remote(remote_url) == "ssh"
    run = make_run(tmp_path, remote)
    with pytest.raises(ProposalError, match="refusing ssh remote"):
        propose(run, remote=remote_url, base_branch="main", allow_simulated=True)


def test_https_push_requires_the_agent_token(monkeypatch):
    url = "https://github.com/org/repo.git"
    assert classify_remote(url) == "https"
    with pytest.raises(ProposalError, match=TOKEN_ENV):
        _credentials(url, needed=True)
    source, env, args = _credentials(url, needed=False)  # clone only: no token needed, none used
    assert source == "agent_token" and env == {} and args == []
    monkeypatch.setenv(TOKEN_ENV, "ghs_agent")
    source, env, args = _credentials(url, needed=True)
    assert env == {TOKEN_ENV: "ghs_agent", "GH_TOKEN": "ghs_agent"}
    assert args[:2] == ["-c", "credential.helper="]  # ambient helpers cleared before the agent helper is added
    assert any("x-access-token" in a for a in args)
    with pytest.raises(ProposalError, match="unrecognized remote"):
        _credentials("ftp://x/y", needed=False)


def test_gh_runs_with_a_minimal_environment(tmp_path, remote, monkeypatch):
    bare, _ = remote
    run = make_run(tmp_path, remote)
    log = tmp_path / "gh.log"
    stub = tmp_path / "gh"
    stub.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{log}"\necho ---ENV--- >> "{log}"\nenv >> "{log}"\n'
                    'echo https://example.invalid/pr/1\n')
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("BR_TEST_SENTINEL", "must-not-leak")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-must-not-leak")
    monkeypatch.setenv(TOKEN_ENV, "ghs_agent")  # set, but a local remote needs no credential
    p = propose(run, remote=str(bare), base_branch="main", push=True, open_pr=True, gh=str(stub), allow_simulated=True)
    assert p.pr_url == "https://example.invalid/pr/1"
    args, env_text = log.read_text().split("---ENV---\n")
    assert "pr\ncreate\n--base\nmain\n--head\nboundaryrun/" in args and "--body-file" in args
    env = dict(line.split("=", 1) for line in env_text.splitlines() if "=" in line)
    assert "BR_TEST_SENTINEL" not in env and "ANTHROPIC_API_KEY" not in env
    assert "GH_TOKEN" not in env and TOKEN_ENV not in env
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["HOME"] == MINIMAL_ENV["HOME"]
    assert set(env) - {"PWD", "SHLVL", "_", "OLDPWD"} <= set(MINIMAL_ENV)
    assert os.environ["BR_TEST_SENTINEL"] == "must-not-leak"
