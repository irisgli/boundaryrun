"""Agent identity and credential isolation for proposals. No Docker, no network.

The agent that opens a PR is a distinct principal: its own name and address, a dedicated
token, and a process environment that carries nothing of the operator's. The operator's
ambient credentials (ssh agent, keychain, gh login) are structurally unreachable.
"""

import os
import subprocess

import pytest

from boundaryrun import propose as pr
from boundaryrun.repo import MINIMAL_ENV, _git


@pytest.mark.parametrize(
    "remote,kind",
    [
        ("https://github.com/o/r.git", "https"),
        ("http://localhost:8080/r.git", "https"),
        ("git@github.com:o/r.git", "ssh"),
        ("ssh://git@github.com/o/r.git", "ssh"),
        ("user@host.example:repo", "ssh"),
        ("file:///tmp/x.git", "local"),
        ("gopher://x", "other"),
    ],
)
def test_remote_classification(remote, kind):
    assert pr.classify_remote(remote) == kind


def test_existing_directory_is_a_local_remote(tmp_path):
    assert pr.classify_remote(str(tmp_path)) == "local"
    assert pr.classify_remote(str(tmp_path / "missing")) == "other"


def test_ssh_remotes_are_refused_because_they_would_use_the_operator_identity():
    with pytest.raises(pr.ProposalError, match="operator's ssh identity"):
        pr._credentials("git@github.com:o/r.git", needed=False)


def test_push_to_https_requires_the_agent_token(monkeypatch):
    monkeypatch.delenv(pr.TOKEN_ENV, raising=False)
    with pytest.raises(pr.ProposalError, match="ambient credentials"):
        pr._credentials("https://github.com/o/r.git", needed=True)
    source, env, args = pr._credentials("https://github.com/o/r.git", needed=False)
    assert source == "agent_token" and env == {} and args == []


def test_agent_token_is_wired_as_the_only_credential_helper(monkeypatch):
    monkeypatch.setenv(pr.TOKEN_ENV, "ghs_agent")
    source, env, args = pr._credentials("https://github.com/o/r.git", needed=True)
    assert source == "agent_token"
    assert env == {pr.TOKEN_ENV: "ghs_agent", "GH_TOKEN": "ghs_agent"}
    assert args[:2] == ["-c", "credential.helper="], "configured helpers (keychain, gh) must be cleared first"
    assert "x-access-token" in args[3] and pr.TOKEN_ENV in args[3]
    assert "ghs_agent" not in " ".join(args), "the token travels in the environment, never on the command line"


def test_local_remotes_need_no_credential(tmp_path):
    assert pr._credentials(str(tmp_path), needed=True) == ("none_local_remote", {}, [])


def test_git_runs_in_a_minimal_environment(monkeypatch, tmp_path):
    """Nothing from the control process leaks into git: a fake API key, a GitHub token and an
    ssh agent socket set on the host are absent inside the git child."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-sentinel")
    monkeypatch.setenv("GH_TOKEN", "gho_operator")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -i /home/op/.ssh/id_ed25519")
    monkeypatch.setenv("BR_SENTINEL", "leak")
    assert set(MINIMAL_ENV) == {"GIT_TERMINAL_PROMPT", "PATH", "HOME"}
    # run a git alias that prints its environment, through the production wrapper
    out = _git(["-c", "alias.env=!env", "env"], cwd=tmp_path)
    for leaked in ("sk-ant-sentinel", "gho_operator", "SSH_AUTH_SOCK", "GIT_SSH_COMMAND", "BR_SENTINEL"):
        assert leaked not in out
    assert "GIT_TERMINAL_PROMPT=0" in out


def test_proposal_default_identity_is_the_agent_not_the_operator():
    p = pr.Proposal(investigation_id="i", branch="b", base_commit="c", body_path="p")
    assert p.identity == f"{pr.AGENT_NAME} <{pr.AGENT_EMAIL}>"
    assert pr.AGENT_EMAIL.endswith(".invalid"), "the agent address must not be a deliverable or claimable mailbox"
    assert p.co_author is None and p.credential_source == "none_local_remote"


def test_operator_git_identity_does_not_reach_the_commit(tmp_path, monkeypatch):
    """A commit made the way `propose` makes it is authored by the agent even when the host
    has a global git identity and GIT_AUTHOR_* set."""
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Operator Person")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "op@example.com")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Operator Person")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "f").write_text("x")
    _git(["add", "f"], cwd=tmp_path)
    _git(["-c", f"user.name={pr.AGENT_NAME}", "-c", f"user.email={pr.AGENT_EMAIL}", "commit", "-q", "--no-gpg-sign", "-m", "m"],
         cwd=tmp_path, env={"GIT_AUTHOR_NAME": pr.AGENT_NAME, "GIT_AUTHOR_EMAIL": pr.AGENT_EMAIL,
                            "GIT_COMMITTER_NAME": pr.AGENT_NAME, "GIT_COMMITTER_EMAIL": pr.AGENT_EMAIL})
    shown = _git(["log", "-1", "--format=%an <%ae>|%cn <%ce>"], cwd=tmp_path)
    assert shown == f"{pr.AGENT_NAME} <{pr.AGENT_EMAIL}>|{pr.AGENT_NAME} <{pr.AGENT_EMAIL}>"
    assert "Operator Person" not in shown and os.environ["GIT_AUTHOR_NAME"] == "Operator Person"
