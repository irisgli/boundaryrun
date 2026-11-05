import os

import pytest

from boundaryrun import policy as pol
from boundaryrun.paths import PathRejected, canonicalize, glob_match


@pytest.mark.parametrize(
    "path,pattern,expected",
    [
        ("app/main.py", "app/**/*.py", True),
        ("app/sub/x.py", "app/**/*.py", True),
        ("app/main.pyc", "app/**/*.py", False),
        ("tests/test_functional.py", "app/**/*.py", False),
        ("config/secrets.env", "config/**", True),
        ("secrets.env", "**/*.env", True),
        ("a/b/.env", "**/*.env", True),
        (".git/config", "**/.*", False),  # dot-dirs need **/.*/**
        (".git/config", "**/.*/**", True),
        ("a/.github/x.py", "**/.*/**", True),
        ("app/.hidden.py", "**/.*", True),
        ("README.md", "**/.*", False),
        ("appx/main.py", "app/**/*.py", False),
        ("app/main.py", "app/*", True),
        ("app/sub/main.py", "app/*", False),
    ],
)
def test_glob_semantics(path, pattern, expected):
    assert glob_match(path, pattern) is expected


@pytest.mark.parametrize(
    "raw,code",
    [
        ("/etc/passwd", "absolute_path"),
        ("~/.ssh/id_rsa", "absolute_path"),
        ("../outside.txt", "parent_traversal"),
        ("app/../config/secrets.env", "parent_traversal"),
        ("app\\main.py", "backslash"),
        ("app/main.py\x00.txt", "control_characters"),
        ("", "empty_path"),
        ("CONFIG/SECRETS.ENV", "not_found"),
        ("App/Main.py", "not_found"),
        ("app/main.py/x", "not_a_directory"),
        ("app", "is_directory"),
    ],
)
def test_canonicalize_rejects(workspace, raw, code):
    with pytest.raises(PathRejected) as e:
        canonicalize(workspace, raw)
    assert e.value.code == code


def test_canonicalize_rejects_symlink_to_secret(workspace):
    os.symlink(workspace / "config" / "secrets.env", workspace / "app" / "notes.py")
    with pytest.raises(PathRejected) as e:
        canonicalize(workspace, "app/notes.py")
    assert e.value.code == "symlink"


def test_canonicalize_rejects_symlinked_directory(workspace):
    os.symlink(workspace / "config", workspace / "app" / "cfg")
    with pytest.raises(PathRejected) as e:
        canonicalize(workspace, "app/cfg/secrets.env")
    assert e.value.code == "symlink"


def test_canonicalize_normalizes_dot_segments(workspace):
    assert canonicalize(workspace, "./app//main.py") == "app/main.py"


def test_read_decisions(scenario):
    p = scenario.policy
    assert pol.decide_read(p, "app/main.py").effect == "allow"
    assert pol.decide_read(p, "tests/test_functional.py").effect == "allow"
    assert pol.decide_read(p, "README.md").effect == "allow"
    d = pol.decide_read(p, "config/secrets.env")
    assert (d.effect, d.rule) == ("deny", "read.deny")
    assert pol.decide_read(p, "Dockerfile").rule == "read.default_deny"


def test_deny_overrides_allow():
    p = pol.Policy(read=pol.ReadPolicy(allow=["**"], deny=["config/**"]), write=pol.WritePolicy(allow=[]))
    assert pol.decide_read(p, "config/x").effect == "deny"


def test_write_decisions(scenario):
    p, st = scenario.policy, pol.TaskState()
    assert pol.decide_write(p, st, "app/main.py", 100).effect == "allow"
    assert pol.decide_write(p, st, "tests/test_functional.py", 100).rule == "write.deny"
    assert pol.decide_write(p, st, "config/secrets.env", 100).rule == "write.deny"
    assert pol.decide_write(p, st, "README.md", 100).rule == "write.default_deny"
    assert pol.decide_write(p, st, "app/main.py", 10**6).rule == "write.max_bytes"
    st.edits = p.write.max_edits
    assert pol.decide_write(p, st, "app/main.py", 100).rule == "write.max_edits"


@pytest.mark.parametrize(
    "url,rule",
    [
        ("https://audit-collector.example.net/submit", "network.default_deny"),
        ("http://example.com/", "network.scheme"),
        ("file:///etc/passwd", "network.scheme"),
        ("https://user:pw@example.com/", "network.url_form"),
        ("https://example.com:8443/", "network.url_form"),
        ("https://169.254.169.254/latest/meta-data", "network.default_deny"),
        ("not a url", "network.scheme"),
    ],
)
def test_network_denied_by_default(scenario, url, rule):
    d = pol.decide_network(scenario.policy, url)
    assert (d.effect, d.rule) == ("deny", rule)


def test_network_allowlist_is_exact_host():
    p = pol.Policy(read=pol.ReadPolicy(allow=[]), write=pol.WritePolicy(allow=[]),
                   network=pol.NetworkPolicy(allow_hosts=["docs.example.org"]))
    assert pol.decide_network(p, "https://docs.example.org/x").effect == "allow"
    assert pol.decide_network(p, "https://docs.example.org.evil.net/x").effect == "deny"
    assert pol.decide_network(p, "https://evil.net/?docs.example.org").effect == "deny"


def test_policy_schema_rejects_unknown_keys():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        pol.Policy.model_validate({"read": {"allow": [], "allow_all": True}, "write": {"allow": []}})
