"""Filesystem helpers: where local state lives and how it is written.

Config, secrets and databases are kept in a "home" directory outside the
source tree. Files are created owner-only (0600) and written atomically.
"""

from __future__ import annotations

import os
import subprocess
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


def restrict_windows(path: Path, directory: bool) -> bool:
    """Windows equivalent of chmod 600/700: drop inherited permissions and
    grant the current user alone full control, using the icacls tool that
    ships with Windows. Returns False when it could not be done."""
    user = os.environ.get("USERNAME")
    if not user:
        return False
    grant = f"{user}:(OI)(CI)F" if directory else f"{user}:F"
    try:
        done = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", grant],
            capture_output=True, timeout=20, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def ensure_private_dir(path: Path) -> None:
    """Create a directory only its owner can enter."""
    path.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        restrict_windows(path, directory=True)
        return
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
        if sys.platform == "win32":
            restrict_windows(Path(tmp_name), directory=False)
        else:
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


def windows_acl_open(path: Path) -> bool:
    """True when a Windows ACL grants access to broad groups (Everyone, Users,
    Authenticated Users). Unknown results count as not open."""
    try:
        done = subprocess.run(["icacls", str(path)], capture_output=True, text=True,
                              timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    text = done.stdout or ""
    return any(name in text for name in ("Everyone:", "BUILTIN\\Users:", "Authenticated Users:"))


def is_private(path: Path) -> bool:
    """True when group and others have no access. On Windows the real ACL is
    inspected instead of POSIX mode bits."""
    if sys.platform == "win32":
        return not windows_acl_open(path)
    try:
        return (path.stat().st_mode & 0o077) == 0
    except OSError:
        return False
