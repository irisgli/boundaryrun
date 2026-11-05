"""Git repository ingestion at a pinned commit.

A target may be a plain directory or a git repository (local path, file:// or https://
URL). Repositories are cloned into the run directory and checked out at an explicit
commit; the resolved commit is recorded in the evidence so a run can be reproduced.
No credentials are handled here: cloning uses whatever git itself can do.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from pydantic import BaseModel

_SHA_RX = re.compile(r"^[0-9a-f]{7,40}$")


class RepoSource(BaseModel):
    url: str
    ref: str  # branch, tag or commit as requested
    commit: str  # resolved full SHA
    subdir: str = ""  # optional path inside the repository that is the target root


class RepoError(RuntimeError):
    pass


def _git(args: list[str], cwd: Path | None = None, timeout: int = 120) -> str:
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False,
                       env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
                            "HOME": str(Path.home())})
    if r.returncode != 0:
        raise RepoError(f"git {args[0]} failed: {r.stderr.strip()[:300]}")
    return r.stdout.strip()


def clone_pinned(url: str, ref: str, dest: Path, subdir: str = "") -> tuple[Path, RepoSource]:
    """Clone `url`, check out `ref`, strip `.git`, and return the target root plus provenance."""
    if dest.exists():
        shutil.rmtree(dest)
    work = dest.parent / (dest.name + ".git-tmp")
    if work.exists():
        shutil.rmtree(work)
    _git(["clone", "--quiet", "--no-checkout", "--filter=blob:none", url, str(work)])
    try:
        if _SHA_RX.match(ref):
            commit = _git(["rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=work)
        else:
            commit = _git(["rev-parse", "--verify", f"origin/{ref}^{{commit}}"], cwd=work) if _remote_has(work, ref) \
                else _git(["rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=work)
        _git(["checkout", "--quiet", "--detach", commit], cwd=work)
        root = work / subdir if subdir else work
        if not root.is_dir() or (subdir and ".." in subdir):
            raise RepoError(f"subdir {subdir!r} not found in repository")
        shutil.rmtree(work / ".git")
        shutil.move(str(root), str(dest)) if subdir else shutil.move(str(work), str(dest))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return dest, RepoSource(url=url, ref=ref, commit=commit, subdir=subdir)


def _remote_has(work: Path, ref: str) -> bool:
    try:
        _git(["rev-parse", "--verify", "--quiet", f"origin/{ref}"], cwd=work)
        return True
    except RepoError:
        return False
