"""Disposable container execution for untrusted code.

Two kinds of untrusted code run here: the target application (including any
agent-authored patch) and its own test suite. Neither ever runs on the host.

Every container gets: no network (or an `--internal` network with no egress for the
probe pair), a read-only root filesystem, read-only source mounts, all Linux
capabilities dropped, no-new-privileges, a non-root UID, pid/memory/CPU limits, a
small noexec tmpfs, no inherited environment, and a wall-clock timeout enforced by
the host. The trusted control process talks to the Docker CLI; containers never get
the Docker socket.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .gateway import TestRun
from .paths import first_match

RUNNER_IMAGE = "boundaryrun-runner:0.1"
_DOCKERFILE = Path(__file__).resolve().parents[2] / "docker" / "runner.Dockerfile"


class SandboxConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    exclude: list[str] = []
    memory: str = "256m"
    cpus: str = "1"
    pids: int = 128
    test_timeout_s: int = 90
    probe_timeout_s: int = 45


class SandboxError(RuntimeError):
    pass


_SENTINEL = ".br-mount-ok"
_MOUNT_FAIL = 97


def _guarded(mount: str, argv: list[str]) -> list[str]:
    """Refuse to run if the bind mount is not visible inside the container.

    Docker silently mounts an empty directory when the host path is outside the
    VM's shared folders (colima, Docker Desktop). Without this check a test run
    would "verify" an empty tree.
    """
    return ["sh", "-c", f'test -f {mount}/{_SENTINEL} || exit {_MOUNT_FAIL}; exec "$@"', "sh", *argv]


def docker_available() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "docker CLI not found"
    r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, check=False)
    if r.returncode != 0:
        return False, f"docker daemon unreachable: {r.stderr.strip()[:200]}"
    return True, r.stdout.strip()


def build_runner_image() -> None:
    subprocess.run(
        ["docker", "build", "-t", RUNNER_IMAGE, "-f", str(_DOCKERFILE), str(_DOCKERFILE.parent)], check=True
    )


def image_present() -> bool:
    return subprocess.run(["docker", "image", "inspect", RUNNER_IMAGE], capture_output=True, check=False).returncode == 0


def export_tree(src: Path, dest: Path, exclude: list[str], *, sentinel: bool = False) -> list[str]:
    """Copy regular files from src to dest, skipping symlinks and excluded paths.

    Returns the sorted list of excluded relative paths (for evidence).
    """
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    skipped: list[str] = []
    for p in sorted(src.rglob("*")):
        rel = p.relative_to(src).as_posix()
        if p.is_symlink() or first_match(rel, exclude) or any(part == "__pycache__" for part in p.parts):
            if p.is_file() or p.is_symlink():
                skipped.append(rel)
            continue
        if p.is_file():  # directories are created only to hold copied files
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p, dest / rel)
    if sentinel:
        (dest / _SENTINEL).write_text("")
    dest.chmod(0o755)
    for p in dest.rglob("*"):
        p.chmod(0o755 if p.is_dir() else 0o644)
    return skipped


class Sandbox:
    def __init__(self, config: SandboxConfig, scratch: Path) -> None:
        self.cfg = config
        self.scratch = scratch
        self.scratch.mkdir(parents=True, exist_ok=True)

    def _base_flags(self, name: str) -> list[str]:
        return [
            "--rm", "--name", name,
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", "65534:65534",
            "--pids-limit", str(self.cfg.pids),
            "--memory", self.cfg.memory, "--memory-swap", self.cfg.memory,
            "--cpus", self.cfg.cpus,
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--label", "boundaryrun=1",
        ]  # fmt: skip

    def _run(self, args: list[str], name: str, timeout: int) -> tuple[int | None, str, str, float, bool]:
        start = time.monotonic()
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr, time.monotonic() - start, False
        except subprocess.TimeoutExpired as e:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
            out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            return None, out, "", time.monotonic() - start, True

    def export(self, src: Path, label: str) -> tuple[Path, list[str]]:
        dest = self.scratch / f"export-{label}-{uuid.uuid4().hex[:8]}"
        skipped = export_tree(src, dest, self.cfg.exclude, sentinel=True)
        return dest, skipped

    def run_functional_tests(self, src: Path) -> TestRun:
        export, _ = self.export(src, "tests")
        name = f"br-tests-{uuid.uuid4().hex[:10]}"
        args = ["docker", "run", *self._base_flags(name), "--network", "none",
                "-v", f"{export}:/work:ro", "-w", "/work", RUNNER_IMAGE,
                *_guarded("/work", ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--color=no", "tests"])]  # fmt: skip
        code, out, err, dur, timed_out = self._run(args, name, self.cfg.test_timeout_s)
        shutil.rmtree(export, ignore_errors=True)
        if code == _MOUNT_FAIL:
            msg = f"source mount not visible in container; is {self.scratch} shared with the Docker VM?"
            return TestRun(exit_code=code, status="error", duration_s=round(dur, 2), output_tail=msg)
        combined = (out + ("\n" + err if err else "")).strip()
        counts = _pytest_counts(combined)
        if timed_out:
            status = "timeout"
        elif code == 0:
            status = "passed"
        elif code == 1:
            status = "failed"
        else:
            status = "error"
        return TestRun(exit_code=code, status=status, duration_s=round(dur, 2), output_tail=combined[-3000:], **counts)

    def run_probe(self, src: Path, probe: Path) -> ProbeRun:
        """Start the app in one container and run the black-box probe in another.

        Both share a fresh `--internal` bridge network: they can reach each other but
        nothing else. The probe container mounts only the probe script.
        """
        export, _ = self.export(src, "app")
        tag = uuid.uuid4().hex[:10]
        net, app_name, probe_name = f"br-net-{tag}", f"br-app-{tag}", f"br-probe-{tag}"
        probe_dir = self.scratch / f"probe-{tag}"
        probe_dir.mkdir()
        shutil.copyfile(probe, probe_dir / "probe.py")
        (probe_dir / _SENTINEL).write_text("")
        (probe_dir / "probe.py").chmod(0o644)
        probe_dir.chmod(0o755)
        start = time.monotonic()
        app_logs, code, out, err, timed_out, setup_error = "", None, "", "", False, None
        try:
            _check(["docker", "network", "create", "--internal", "--label", "boundaryrun=1", net])
            app_args = ["docker", "run", "-d", *self._base_flags(app_name), "--network", net,
                        "-v", f"{export}:/work:ro", "-w", "/work", RUNNER_IMAGE,
                        *_guarded("/work", ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"])]  # fmt: skip
            _check(app_args)
            p_args = ["docker", "run", *self._base_flags(probe_name), "--network", net,
                      "-v", f"{probe_dir}:/verifier:ro", RUNNER_IMAGE,
                      *_guarded("/verifier", ["python", "-I", "/verifier/probe.py", f"http://{app_name}:8000"])]  # fmt: skip
            code, out, err, _, timed_out = self._run(p_args, probe_name, self.cfg.probe_timeout_s)
            if code == _MOUNT_FAIL:
                raise SandboxError("probe mount not visible in container; is the scratch dir shared with the Docker VM?")
            logs = subprocess.run(["docker", "logs", app_name], capture_output=True, text=True, check=False)
            app_logs = (logs.stdout + logs.stderr)[-2000:]
        except SandboxError as e:
            setup_error = str(e)
        finally:
            subprocess.run(["docker", "rm", "-f", app_name], capture_output=True, check=False)
            subprocess.run(["docker", "network", "rm", net], capture_output=True, check=False)
            shutil.rmtree(export, ignore_errors=True)
            shutil.rmtree(probe_dir, ignore_errors=True)
        dur = round(time.monotonic() - start, 2)
        if setup_error:
            return ProbeRun(ok=False, error=setup_error, duration_s=dur)
        if timed_out:
            return ProbeRun(ok=False, error="probe timed out", duration_s=dur, app_log_tail=app_logs)
        try:
            lines = [ln for ln in out.strip().splitlines() if ln.strip()]
            result = ProbeResult.model_validate(json.loads(lines[-1]))
        except Exception as e:
            return ProbeRun(ok=False, error=f"unparseable probe output ({type(e).__name__}); exit={code} {err[-300:]}",
                            duration_s=dur, app_log_tail=app_logs)
        return ProbeRun(ok=True, result=result, duration_s=dur, app_log_tail=app_logs)


class ProbeCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    kind: str
    status_code: int | None
    content_returned: bool
    outcome: str
    error: str | None = None


class ProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    healthy: bool
    error: str | None
    checks: list[ProbeCheck]


class ProbeRun(BaseModel):
    ok: bool
    result: ProbeResult | None = None
    error: str | None = None
    duration_s: float
    app_log_tail: str = ""


def _check(args: list[str]) -> None:
    r = subprocess.run(args, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        raise SandboxError(f"{' '.join(args[:3])} failed: {r.stderr.strip()[:300]}")


_COUNT_RX = re.compile(r"(\d+) (passed|failed|errors?)")


def _pytest_counts(text: str) -> dict[str, int]:
    """Parse pytest's final summary line. Advisory only: the exit code is authoritative."""
    counts = {"passed": 0, "failed": 0, "errors": 0}
    lines = [ln for ln in text.splitlines() if re.search(r"\b(passed|failed|error)", ln)]
    if lines:
        for n, kind in _COUNT_RX.findall(lines[-1]):
            counts["errors" if kind.startswith("error") else kind] = int(n)
    return counts
