"""Tests for scripts/audit-footprints.

Planted footprints are assembled at run time (and one word is spelled
backwards) so that this file passes the audit it is testing.
"""

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "audit-footprints"
AUTHOR = ["-c", "user.name=Wu-Falin", "-c", "user.email=valynndo" + "@" + "gmail.com",
          "-c", "commit.gpgsign=false"]


def git(repo, *args, identity=AUTHOR):
    subprocess.run(["git", "-C", str(repo), *identity, *args], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def audit(repo, *args):
    result = subprocess.run([sys.executable, str(SCRIPT), "--root", str(repo), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.returncode, result.stdout


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "ok.txt").write_text(
        "contact: someone@example.com\n"
        "listen on 127.0.0.1, docs use 192.0.2.10 and 2001:db8::1\n"
        "Chrome/126.0.0.0 is a version, 12:30:45 is a time\n",
        encoding="utf-8",
    )
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "Add notes")
    return tmp_path


def test_clean_repository_passes(repo):
    code, out = audit(repo)
    assert code == 0, out
    assert "clean" in out


PLANTED = {
    "email": "mail me at jane.doe" + "@" + "corp-mail.io",
    "ip-address": "server is at 10." + "20.30.40",
    "mac-address": "nic 3c:" + "22:fb:" + "a1:b2:c3",
    "home-path": "see /ho" + "me/alice/notes",
    "tool-name": "made with " + "edualc"[::-1],
    "attribution-phrase": "yB-derohtuA-oC"[::-1] + ": somebody",
}


@pytest.mark.parametrize("category", sorted(PLANTED))
def test_each_footprint_is_found_in_the_tree(repo, category):
    (repo / "leak.txt").write_text(PLANTED[category] + "\n", encoding="utf-8")
    code, out = audit(repo, "--no-history")
    assert code == 1
    assert f"[{category}] tree:leak.txt:1" in out


def test_other_footprint_shapes(repo):
    (repo / "more.txt").write_text(
        "C:\\Us" + "ers\\bob\\file\n"
        + ":".join(["fe80", "", "1ff", "fe23", "4567", "890a"]) + "\n"
        "uses " + "tpgtahc"[::-1].upper() + " daily\n"
        "x" + "ciporhtna"[::-1] + "y inside a longer word\n"
        "this was " + "detsissa-IA"[::-1] + "\n",
        encoding="utf-8",
    )
    _, out = audit(repo, "--no-history")
    for number, category in ((1, "home-path"), (2, "ip-address"), (3, "tool-name"),
                             (4, "tool-name"), (5, "attribution-phrase")):
        assert f"[{category}] tree:more.txt:{number}" in out, out


def test_footprints_removed_from_the_tree_are_still_found_in_history(repo):
    (repo / "leak.txt").write_text(PLANTED["email"] + "\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "Add leak")
    git(repo, "rm", "-q", "leak.txt")
    git(repo, "commit", "-q", "-m", "Remove leak")
    assert audit(repo, "--no-history")[0] == 0
    code, out = audit(repo)
    assert code == 1
    assert "[email] history:" in out and "leak.txt" in out


def test_foreign_author_committer_and_message_are_found(repo):
    other = ["-c", "user.name=Someone Else", "-c", "user.email=else" + "@" + "corp-mail.io",
             "-c", "commit.gpgsign=false"]
    (repo / "b.txt").write_text("fine\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "Change\n\n" + "yb-derohtua-oC"[::-1] + ": x <x@example.com>",
        identity=other)
    code, out = audit(repo)
    assert code == 1
    assert "[identity]" in out and "author is Someone Else" in out
    assert "committer is Someone Else" in out
    assert "[attribution-phrase]" in out and "(message)" in out


def test_branch_and_file_names_are_checked(repo):
    name = "edualc"[::-1]
    git(repo, "branch", f"{name}/session-1")
    (repo / f"{name.upper()}.md").write_text("notes\n", encoding="utf-8")
    code, out = audit(repo)
    assert code == 1
    assert "[tool-name] ref:refs/heads/" in out
    assert "(file name)" in out


def test_ignore_file_may_name_agent_config(repo):
    name = "edualc"[::-1]
    (repo / ".gitignore").write_text(f".{name}/\n{name.upper()}.md\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "Ignore agent config")
    assert audit(repo)[0] == 0


def test_image_metadata_is_found(repo):
    (repo / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 16 + b"tEXtComment\0hello")
    code, out = audit(repo, "--no-history")
    assert code == 1 and "[image-metadata] tree:logo.png" in out


def test_this_repository_is_clean():
    root = SCRIPT.parent.parent
    if not (root / ".git").exists():
        pytest.skip("not a git checkout")
    code, out = audit(root)
    assert code == 0, out
