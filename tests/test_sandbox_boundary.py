"""Container boundary tests. Hostile code runs through the production code paths
(`run_functional_tests` and `run_probe`) and asserts the restrictions from inside."""

import subprocess
import textwrap

import pytest

from boundaryrun.sandbox import Sandbox, SandboxConfig

pytestmark = pytest.mark.docker

HOSTILE_TESTS = textwrap.dedent(
    """
    import os, socket, subprocess, pytest

    def test_no_outbound_ip():
        with pytest.raises(OSError):
            socket.create_connection(("1.1.1.1", 443), timeout=3)

    def test_no_dns():
        with pytest.raises(OSError):
            socket.getaddrinfo("example.com", 443)

    def test_source_mount_read_only():
        with pytest.raises(OSError):
            open("/work/pwned.txt", "w")

    def test_root_fs_read_only():
        with pytest.raises(OSError):
            open("/etc/pwned", "w")

    def test_non_root():
        assert os.getuid() == 65534 and os.getgid() == 65534

    def test_no_capabilities_and_no_new_privs():
        status = dict(l.split(":", 1) for l in open("/proc/self/status").read().splitlines() if ":" in l)
        assert int(status["CapEff"].strip(), 16) == 0
        assert int(status["CapBnd"].strip(), 16) == 0
        assert status["NoNewPrivs"].strip() == "1"

    def test_secrets_not_exported():
        assert not os.path.exists("/work/config/secrets.env")
        assert not os.path.exists("/work/config")

    def test_tmp_is_noexec():
        path = "/tmp/x.sh"
        with open(path, "w") as f:
            f.write("#!/bin/sh\\necho hi\\n")
        os.chmod(path, 0o755)
        with pytest.raises(PermissionError):
            subprocess.run([path])

    def test_no_docker_socket():
        assert not os.path.exists("/var/run/docker.sock")

    def test_no_host_credentials_in_env():
        assert not any(k.startswith("ANTHROPIC") for k in os.environ)
        assert "BR_HOST_SENTINEL" not in os.environ

    def test_memory_limit_applied():
        limit = open("/sys/fs/cgroup/memory.max").read().strip()
        assert limit != "max" and int(limit) <= 256 * 1024 * 1024
    """
)


def test_untrusted_tests_run_inside_restricted_container(workspace, scenario, tmp_path, monkeypatch):
    monkeypatch.setenv("BR_HOST_SENTINEL", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key-host-only")
    (workspace / "tests" / "test_hostile.py").write_text(HOSTILE_TESTS)
    sb = Sandbox(scenario.sandbox, tmp_path / "sb")
    r = sb.run_functional_tests(workspace)
    assert r.status == "passed", r.output_tail
    assert r.passed == 7 + 11


def test_timeout_kills_container(workspace, scenario, tmp_path):
    (workspace / "tests" / "test_hang.py").write_text("import time\n\ndef test_hang():\n    time.sleep(600)\n")
    cfg = scenario.sandbox.model_copy(update={"test_timeout_s": 8})
    r = Sandbox(cfg, tmp_path / "sb").run_functional_tests(workspace)
    assert r.status == "timeout" and r.exit_code is None
    left = subprocess.run(["docker", "ps", "-q", "--filter", "label=boundaryrun=1", "--filter", "name=br-tests-"],
                          capture_output=True, text=True).stdout.strip()
    assert left == ""


def test_app_container_has_no_egress(workspace, scenario, tmp_path):
    """The patched app runs on an --internal network. This app refuses to start if it
    can reach the internet, so a healthy probe result proves egress was blocked."""
    main = workspace / "app" / "main.py"
    main.write_text(
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 443), timeout=3).close()\n"
        "    raise SystemExit('egress available')\n"
        "except OSError:\n"
        "    pass\n" + main.read_text()
    )
    run = Sandbox(scenario.sandbox, tmp_path / "sb").run_probe(workspace, scenario.probe)
    assert run.ok and run.result.healthy, (run.error, run.app_log_tail)


def test_fork_bomb_is_bounded(workspace, scenario, tmp_path):
    (workspace / "tests" / "test_fork.py").write_text(
        "import os, signal, pytest\n\n"
        "def test_pids_limited():\n"
        "    pids = []\n"
        "    try:\n"
        "        with pytest.raises(OSError):\n"
        "            for _ in range(1000):\n"
        "                pid = os.fork()\n"
        "                if pid == 0:\n"
        "                    import time; time.sleep(30); os._exit(0)\n"
        "                pids.append(pid)\n"
        "        assert len(pids) < 128\n"
        "    finally:\n"
        "        for pid in pids:\n"
        "            os.kill(pid, signal.SIGKILL)\n"
        "            os.waitpid(pid, 0)\n"
    )
    cfg = SandboxConfig.model_validate({**scenario.sandbox.model_dump(), "test_timeout_s": 60})
    r = Sandbox(cfg, tmp_path / "sb").run_functional_tests(workspace)
    assert r.status == "passed", r.output_tail
