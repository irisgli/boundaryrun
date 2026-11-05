"""Git ingestion at a pinned commit and the controlled proposal workflow (local bare remote, stubbed gh)."""

import json
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
    log = tmp_path / "gh.log"
    stub = tmp_path / "gh"
    # gh runs with a minimal environment, so the log path is baked into the stub rather than passed through env.
    stub.write_text(f'#!/bin/sh\necho "$@" > "{log}"\necho https://example.invalid/pr/1\n')
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(ProposalError, match="requires --push"):
        propose(verified_run, remote=str(remote[0]), base_branch="main", open_pr=True, gh=str(stub), allow_simulated=True)
    p = propose(verified_run, remote=str(remote[0]), base_branch="main", push=True, open_pr=True, gh=str(stub),
                allow_simulated=True)
    assert p.pr_url == "https://example.invalid/pr/1"
    args = log.read_text()
    assert "pr create --base main --head boundaryrun/" in args and "--body-file" in args
    assert json.loads((verified_run / "proposal.json").read_text())["pr_url"] == p.pr_url
    assert git("log", "-1", "--format=%an <%ae>", p.commit, cwd=remote[0]) == "BoundaryRun Agent <agent@boundaryrun.invalid>"


@pytest.fixture(scope="module")
def needs_review_run(remote, tmp_path_factory):
    """The good fix plus the comment_backdoor edit, with no attack planted: the new seed identity is
    caught by the static before/after comparison, not by policy, and the run needs a human."""
    bare, _ = remote
    report, path = run_investigation(SCENARIO, agent_mode="fixture", fixture="needs_review",
                                     runs_dir=tmp_path_factory.mktemp("runs"), repo=(str(bare), "main", "docvault"))
    assert report.verdict.status.value == "needs_review", report.verdict.reasons
    assert report.policy_summary.denied == 0
    assert [f.rule_id for f in report.static_analysis.introduced] == ["boundaryrun.docvault.seed-identity"]
    assert {r.id: r.status for r in report.requirements} == {"R1": "satisfied", "R2": "satisfied", "R3": "satisfied",
                                                              "R4": "not_assessed"}
    assert report.claim_check.consistent and report.claim_check.files_changed == ["app/main.py", "app/store.py"]
    assert report.flow.untrusted_input and not report.flow.external_communication
    return path.parent


def test_needs_review_releases_only_with_a_bound_approval(needs_review_run, remote):
    from boundaryrun.approval import record_approval

    bare, head = remote
    with pytest.raises(ProposalError, match="no human approval"):
        propose(needs_review_run, remote=str(bare), base_branch="main", allow_simulated=True)
    record_approval(needs_review_run, reviewer="Iris", decision="approve", note="break-glass token is a test fixture")
    p = propose(needs_review_run, remote=str(bare), base_branch="main", push=True, allow_simulated=True)
    assert p.approval["reviewer"] == "Iris" and p.trailers["Verdict"] == "needs_review"
    assert sorted(git("diff", "--name-only", f"{head}..{p.commit}", cwd=bare).splitlines()) == \
        ["docvault/app/main.py", "docvault/app/store.py"]
    body = (needs_review_run / "pr_body.md").read_text()
    assert "Verdict: **needs_review**" in body and "Human approval: **approve** by Iris" in body
    assert "| R1 | T1 | satisfied |" in body
    record_approval(needs_review_run, reviewer="Iris", decision="reject")
    with pytest.raises(ProposalError, match="rejected by Iris"):
        propose(needs_review_run, remote=str(bare), base_branch="main", allow_simulated=True)
