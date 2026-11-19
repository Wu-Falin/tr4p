"""Portability checks: odd paths, Windows permissions, old Python, no PATH."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

from tr4p import doctor, fsutil
from tr4p.cli import main
from tr4p.config import CONFIG_FILE

ODD = "my tr4p \u00e9\u00e8 \u65e5\u672c data"


def test_home_with_spaces_and_non_ascii_works_end_to_end(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp) / ODD
        with mock.patch.dict(os.environ, {"TR4P_HOME": str(home)}):
            assert main(["init", "--yes", "--mode", "standalone"]) == 0
            assert (home / CONFIG_FILE).exists()
            assert main(["doctor"]) in (0, 1)       # runs without crashing on the odd path
        assert "Checking" in capsys.readouterr().out


def test_write_private_is_owner_only_and_atomic():
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / ODD / "secret"
        fsutil.write_private(target, b"x")
        assert target.read_bytes() == b"x"
        assert fsutil.is_private(target)
        fsutil.write_private(target, b"y")
        assert target.read_bytes() == b"y"
        assert not [p for p in target.parent.iterdir() if p.name.startswith(".tmp-")]


def test_windows_permissions_use_icacls_for_the_current_user_only():
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    with mock.patch.object(sys, "platform", "win32"), \
            mock.patch.dict(os.environ, {"USERNAME": "alice"}), \
            mock.patch("tr4p.fsutil.subprocess.run", fake_run), \
            tempfile.TemporaryDirectory() as tmp:
        fsutil.ensure_private_dir(Path(tmp) / "home")
        fsutil.write_private(Path(tmp) / "home" / "f", b"x")
    assert calls[0][0] == "icacls" and "/inheritance:r" in calls[0]
    assert calls[0][-1] == "alice:(OI)(CI)F"          # directory: inherited by its files
    assert any(c[-1] == "alice:F" for c in calls)      # file: this user only


def test_windows_acl_open_detects_broad_groups():
    def listing(text):
        return lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=text, stderr="")
    with mock.patch("tr4p.fsutil.subprocess.run", listing("C:\\x BUILTIN\\Users:(R)\n")):
        assert fsutil.windows_acl_open(Path("x"))
    with mock.patch("tr4p.fsutil.subprocess.run", listing("C:\\x ALICE\\alice:(F)\n")):
        assert not fsutil.windows_acl_open(Path("x"))
    with mock.patch("tr4p.fsutil.subprocess.run", side_effect=OSError):
        assert not fsutil.windows_acl_open(Path("x"))   # no icacls: nothing to complain about


def test_missing_icacls_never_breaks_writing():
    with mock.patch.object(sys, "platform", "win32"), \
            mock.patch.dict(os.environ, {"USERNAME": "alice"}), \
            mock.patch("tr4p.fsutil.subprocess.run", side_effect=OSError), \
            tempfile.TemporaryDirectory() as tmp:
        fsutil.write_private(Path(tmp) / "f", b"x")
        assert (Path(tmp) / "f").read_bytes() == b"x"


def test_doctor_explains_a_missing_path_entry(capsys):
    report = doctor.Report()
    with mock.patch("tr4p.doctor.shutil.which", return_value=None):
        doctor._platform(report)
    out = capsys.readouterr().out
    assert "not on PATH" in out and "python -m tr4p" in out and "PATH" in out.split("python -m tr4p")[1]
    assert report.warned >= 1


def test_old_python_gets_a_friendly_message_not_a_traceback():
    code = ("import sys; sys.version_info = (3, 9, 0, 'final', 0); "
            "import runpy; runpy.run_module('tr4p', run_name='x')")
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          cwd=str(Path(__file__).resolve().parents[1] / "src"))
    assert done.returncode == 1
    assert "needs Python 3.10 or newer" in done.stderr and "Traceback" not in done.stderr


def test_config_with_windows_line_endings_loads():
    from tr4p.config import Config
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "config.json"
        Config().save(path)
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        assert Config.load(path).public.port == Config().public.port


def test_path_hint_survives_python_builds_without_a_user_scheme():
    with mock.patch("tr4p.doctor.sysconfig.get_path", side_effect=KeyError("osx_user")):
        hint = doctor._path_hint()
    assert "PATH" in hint and "KeyError" not in hint
