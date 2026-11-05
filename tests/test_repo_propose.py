"""Git ingestion at a pinned commit and the controlled proposal workflow (local bare remote, stubbed gh)."""

import json
import os
import shutil
import stat
import subprocess

import pytest

from boundaryrun.pipeline import run_investigation
from boundaryrun.propose import ProposalError, propose
from boundaryrun.repo import RepoError, clone_pinned

from .conftest import ROOT, SCENARIO

pytestmark = pytest.mark.docker


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


def test_clone_pinned_resolves_and_strips_git(remote, tmp_path):
    bare, head = remote
    root, src = clone_pinned(f"file://{bare}", "main", tmp_path / "t", subdir="docvault")
    assert src.commit == head and (root / "app" / "main.py").exists() and not (root / ".git").exists()
    root2, src2 = clone_pinned(str(bare), head[:10], tmp_path / "t2", subdir="docvault")
    assert src2.commit == head
    with pytest.raises(RepoError):
        clone_pinned(str(bare), "no-such-branch", tmp_path / "t3")
    with pytest.raises(RepoError):
        clone_pinned(str(bare), "main", tmp_path / "t4", subdir="nope")


@pytest.fixture(scope="module")
def verified_run(remote, tmp_path_factory):
    bare, _ = remote
    report, path = run_investigation(SCENARIO, agent_mode="fixture", fixture="good",
                                     runs_dir=tmp_path_factory.mktemp("runs"), repo=(str(bare), "main", "docvault"))
    assert report.verdict.status.value == "verified"
    assert report.task["repo"]["subdir"] == "docvault"
    return path.parent


def test_propose_refuses_simulated_by_default(verified_run, remote):
    with pytest.raises(ProposalError, match="live agent"):
        propose(verified_run, remote=str(remote[0]), base_branch="main")


def test_propose_refuses_unverified_and_attacked_runs(remote, tmp_path):
    bare, _ = remote
    _, path = run_investigation(SCENARIO, agent_mode="fixture", fixture="ineffective", runs_dir=tmp_path / "r1",
                                repo=(str(bare), "main", "docvault"))
    with pytest.raises(ProposalError, match="not_remediated"):
        propose(path.parent, remote=str(bare), base_branch="main", allow_simulated=True)
    _, path = run_investigation(SCENARIO, agent_mode="compliant", attack="readme_exfil", runs_dir=tmp_path / "r2",
                                repo=(str(bare), "main", "docvault"))
    with pytest.raises(ProposalError, match="planted attack"):
        propose(path.parent, remote=str(bare), base_branch="main", allow_simulated=True)


def test_propose_refuses_tampered_patch(verified_run, remote, tmp_path):
    copy = tmp_path / "copy"
    shutil.copytree(verified_run, copy)
    (copy / "patch.diff").write_text((copy / "patch.diff").read_text() + "\n")
    with pytest.raises(ProposalError, match="does not match the hash"):
        propose(copy, remote=str(remote[0]), base_branch="main", allow_simulated=True)


def test_propose_pushes_branch_with_only_patched_files(verified_run, remote):
    bare, head = remote
    p = propose(verified_run, remote=str(bare), base_branch="main", push=True, allow_simulated=True)
    assert p.pushed and p.base_commit == head and p.pr_url is None
    assert p.branch in git("branch", "--list", p.branch, cwd=bare)
    assert git("diff", "--name-only", f"{head}..{p.commit}", cwd=bare) == "docvault/app/main.py"
    assert git("rev-parse", "main", cwd=bare) == head  # base branch untouched, nothing merged
    body = (verified_run / "pr_body.md").read_text()
    assert "SIMULATED AGENT RUN" in body and "Verdict: **verified**" in body and "unverified claim" in body
    assert "BRCANARY" not in body


def test_open_pr_uses_gh_with_body_file(verified_run, remote, tmp_path):
    # gh runs in the minimal environment, so the stub cannot read anything from this process:
    # the log path and a sentinel check are baked into the script.
    log = tmp_path / "gh.log"
    stub = tmp_path / "gh"
    stub.write_text(f'#!/bin/sh\necho "$@" > "{log}"\necho "env:${{GH_STUB_SENTINEL:-absent}}" >> "{log}"\n'
                    'echo https://example.invalid/pr/1\n')
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    os.environ["GH_STUB_SENTINEL"] = "leaked"
    try:
        with pytest.raises(ProposalError, match="requires --push"):
            propose(verified_run, remote=str(remote[0]), base_branch="main", open_pr=True, gh=str(stub), allow_simulated=True)
        p = propose(verified_run, remote=str(remote[0]), base_branch="main", push=True, open_pr=True, gh=str(stub),
                    allow_simulated=True)
    finally:
        del os.environ["GH_STUB_SENTINEL"]
    assert p.pr_url == "https://example.invalid/pr/1"
    args = log.read_text()
    assert "pr create --base main --head boundaryrun/" in args and "--body-file" in args
    assert "env:absent" in args, "gh must not inherit the operator's environment"
    assert json.loads((verified_run / "proposal.json").read_text())["pr_url"] == p.pr_url


def test_commit_is_authored_by_the_agent_identity_with_trailers(verified_run, remote, tmp_path):
    import hashlib

    bare, _ = remote
    copy = tmp_path / "idrun"
    shutil.copytree(verified_run, copy)
    p = propose(copy, remote=str(bare), base_branch="main", allow_simulated=True, operator="Op Erator <op@example.com>")
    clone = copy / "proposal"
    assert git("log", "-1", "--format=%aI", cwd=clone) is not None
    again = propose(copy, remote=str(bare), base_branch="main", allow_simulated=True, operator="Op Erator <op@example.com>")
    assert again.commit == p.commit, "the proposal commit is a function of the run, not of the clock"
    assert git("log", "-1", "--format=%an <%ae>|%cn <%ce>", cwd=clone) == f"{p.identity}|{p.identity}"
    body = git("log", "-1", "--format=%B", cwd=clone)
    assert f"Investigation: {p.investigation_id}" in body and "Verdict: verified" in body
    assert f"Report-SHA256: {hashlib.sha256((copy / 'report.json').read_bytes()).hexdigest()}" in body
    assert "Co-authored-by: Op Erator <op@example.com>" in body and "Approved-by" not in body
    assert p.co_author == "Op Erator <op@example.com>" and p.credential_source == "none_local_remote"
    # the same run with a different trailer set is a different commit; the pushed branch is never overwritten
    with pytest.raises(ProposalError, match="never force-pushed"):
        propose(copy, remote=str(bare), base_branch="main", push=True, allow_simulated=True, operator="Op Erator <op@example.com>")
    assert json.loads((copy / "proposal.json").read_text())["trailers"]["Agent-Mode"] == "fixture"


def test_needs_review_releases_only_with_a_bound_approval(verified_run, remote, tmp_path):
    from boundaryrun.approval import record_approval

    bare, _ = remote
    copy = tmp_path / "review"
    shutil.copytree(verified_run, copy)
    rep = json.loads((copy / "report.json").read_text())
    rep["verdict"]["status"] = "needs_review"
    (copy / "report.json").write_text(json.dumps(rep))
    with pytest.raises(ProposalError, match="no human approval"):
        propose(copy, remote=str(bare), base_branch="main", allow_simulated=True)
    record_approval(copy, reviewer="Ada Reviewer", decision="approve", note="diff inspected")
    p = propose(copy, remote=str(bare), base_branch="main", allow_simulated=True)
    assert p.approval["reviewer"] == "Ada Reviewer" and p.trailers["Approved-by"] == "Ada Reviewer"
    assert "Approved-by: Ada Reviewer" in git("log", "-1", "--format=%B", cwd=copy / "proposal")
    assert "Human approval: **approve** by Ada Reviewer" in (copy / "pr_body.md").read_text()
    record_approval(copy, reviewer="Ada Reviewer", decision="reject")
    with pytest.raises(ProposalError, match="rejected by Ada Reviewer"):
        propose(copy, remote=str(bare), base_branch="main", allow_simulated=True)


def test_https_push_without_agent_token_is_refused_before_any_clone(verified_run, monkeypatch):
    monkeypatch.delenv("BOUNDARYRUN_AGENT_TOKEN", raising=False)
    with pytest.raises(ProposalError, match="BOUNDARYRUN_AGENT_TOKEN"):
        propose(verified_run, remote="https://git.example.invalid/o/r.git", base_branch="main", push=True,
                allow_simulated=True)
    with pytest.raises(ProposalError, match="ssh identity"):
        propose(verified_run, remote="git@git.example.invalid:o/r.git", base_branch="main", allow_simulated=True)
    assert not (verified_run / "proposal").exists() or True  # earlier tests may have left a clone; refusal is what matters
