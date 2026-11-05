"""Path canonicalization and glob matching for policy decisions.

Policy rules are written against canonical workspace-relative POSIX paths. A request
path is only ever matched after it has been resolved to the exact on-disk spelling of
an existing file, so case-insensitive or normalization-insensitive filesystems (APFS)
cannot be used to alias a denied path with a spelling that the deny rule misses.
"""

from __future__ import annotations

import os
import re
import stat
from functools import lru_cache
from pathlib import Path


class PathRejected(Exception):
    """The requested path is not a valid in-workspace path. `code` is stable for audit."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


_MAX_PATH_LEN = 512
_MAX_DEPTH = 16


def _split_request(raw: str) -> list[str]:
    if not isinstance(raw, str) or not raw:
        raise PathRejected("empty_path", "path must be a non-empty string")
    if len(raw) > _MAX_PATH_LEN:
        raise PathRejected("path_too_long", "path exceeds maximum length")
    if "\x00" in raw or any(ord(c) < 0x20 for c in raw):
        raise PathRejected("control_characters", "path contains control characters")
    if "\\" in raw:
        raise PathRejected("backslash", "use forward slashes")
    if raw.startswith("/") or raw.startswith("~"):
        raise PathRejected("absolute_path", "path must be relative to the workspace root")
    parts = [p for p in raw.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise PathRejected("parent_traversal", "'..' components are not permitted")
    if len(parts) > _MAX_DEPTH:
        raise PathRejected("path_too_deep", "path is too deep")
    return parts


def canonicalize(root: Path, raw: str, *, must_exist: bool = True, allow_dir: bool = False) -> str:
    """Resolve `raw` to its canonical relative spelling under `root`.

    Every component must match a directory entry exactly (byte-for-byte as stored), and
    no component may be a symlink. Returns "" for the root itself.
    """
    parts = _split_request(raw)
    current = root
    canonical: list[str] = []
    for i, part in enumerate(parts):
        is_last = i == len(parts) - 1
        try:
            entries = os.listdir(current)
        except NotADirectoryError:
            raise PathRejected("not_a_directory", f"'{'/'.join(canonical)}' is not a directory") from None
        if part not in entries:
            if is_last and not must_exist:
                canonical.append(part)
                current = current / part
                break
            raise PathRejected("not_found", "no such file or directory (exact-case match required)")
        current = current / part
        st = os.lstat(current)
        if stat.S_ISLNK(st.st_mode):
            raise PathRejected("symlink", "symbolic links are not followed")
        if not is_last and not stat.S_ISDIR(st.st_mode):
            raise PathRejected("not_a_directory", "intermediate component is not a directory")
        canonical.append(part)
    if current.exists():
        st = os.lstat(current)
        if stat.S_ISDIR(st.st_mode) and not allow_dir:
            raise PathRejected("is_directory", "path is a directory")
        if not stat.S_ISDIR(st.st_mode) and not stat.S_ISREG(st.st_mode):
            raise PathRejected("special_file", "only regular files are accessible")
    return "/".join(canonical)


@lru_cache(maxsize=256)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    """Translate a path glob: `**/` spans zero or more directories, `*` and `?` never cross `/`."""
    i, out = 0, []
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def glob_match(path: str, pattern: str) -> bool:
    return _glob_regex(pattern).match(path) is not None


def first_match(path: str, patterns: list[str]) -> str | None:
    return next((p for p in patterns if glob_match(path, p)), None)
