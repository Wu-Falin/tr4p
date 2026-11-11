"""Filesystem helpers: where local state lives and how it is written.

Config, secrets and databases are kept in a "home" directory outside the
source tree. Files are created owner-only (0600) and written atomically.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ENV_HOME = "TR4P_HOME"


def default_home() -> Path:
    """Return the per-user state directory for this platform."""
    override = os.environ.get(ENV_HOME)
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("APPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Roaming"
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        base = os.environ.get("XDG_CONFIG_HOME")
        root = Path(base) if base else Path.home() / ".config"
    return root / "tr4p"


def ensure_private_dir(path: Path) -> None:
    """Create a directory only its owner can enter (best effort on Windows)."""
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def write_private(path: Path, data: bytes) -> None:
    """Atomically write an owner-only file."""
    ensure_private_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(tmp_name, 0o600)
        except OSError:
            pass
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def is_private(path: Path) -> bool:
    """True when group and others have no access. Always True on Windows,
    where POSIX mode bits do not describe the real ACL."""
    if sys.platform == "win32":
        return True
    try:
        return (path.stat().st_mode & 0o077) == 0
    except OSError:
        return False
