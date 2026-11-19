# Installing, upgrading and removing TR4P

TR4P is pure Python with one dependency (aiohttp). It runs as an ordinary
user; it never needs root or administrator rights.

## What is tested

"Tested in CI" means a job runs on every release check and passes. "Best
effort" means it should work, nobody runs it automatically, and bug reports
are welcome.

| Platform | Status |
| --- | --- |
| Python 3.10 and 3.13 on Linux (x86_64) | tested in CI, every push |
| Python 3.12 quickstart on Linux, Windows, macOS | tested in CI |
| Windows (Server 2022 runner), Python 3.10 and 3.13 | tested in CI, full suite |
| macOS (Apple silicon runner), Python 3.13 | tested in CI, full suite |
| Debian 12, Ubuntu 22.04 / 24.04, Fedora 41, Alpine 3.21 (distro Python, venv) | tested in CI, quickstart |
| Docker image, linux/amd64 | tested in CI, full smoke flow |
| Docker image, linux/arm64 | built and started under emulation in CI |
| Python 3.11, 3.12 and newer than 3.13 | best effort (same code, not run separately) |
| Linux arm64 native, Raspberry Pi OS | best effort; a CI job exists but is off by default |
| macOS Intel, Homebrew Python | best effort |
| Windows 10 / 11 desktop, other Linux distributions | best effort |
| Python 3.9 and older | not supported; you get a clear message |

TR4P detects automated visitors by behaviour. It does not promise to catch
every one, and it is for sites you own or are authorized to protect.

## Install

Recommended, because it needs no virtual environment of your own:

```bash
pipx install git+https://github.com/Wu-Falin/tr4p
```

Or in a virtual environment, which is also what to use when pip says
`externally-managed-environment` (PEP 668, current Debian, Ubuntu, Fedora and
Homebrew Python):

```bash
python3 -m venv ~/tr4p-venv
~/tr4p-venv/bin/pip install .
~/tr4p-venv/bin/tr4p init --yes --mode standalone
```

On Windows: `py -m venv %USERPROFILE%\tr4p-venv`, then
`%USERPROFILE%\tr4p-venv\Scripts\pip install .`.

Do not use `--break-system-packages`.

### `tr4p` is not found

`python -m tr4p` always works (`py -m tr4p` on Windows). To get the short
command, add pip's script folder to PATH; `tr4p doctor` prints the exact line
for your machine.

### Paths and files

State lives in `~/.config/tr4p` (Linux), `~/Library/Application Support/tr4p`
(macOS) or `%APPDATA%\tr4p` (Windows); set `TR4P_HOME` to move it. Spaces and
non-ASCII characters in the path are fine. Files are created owner-only: mode
0600 on Linux and macOS, and on Windows an ACL that grants only your account
(set with the built-in `icacls`; `tr4p doctor` warns if it finds broad groups
such as Everyone or Users on the folder). Line endings in the config file are
read either way (CRLF or LF).

### If aiohttp has no compiled build for your platform

TR4P still works: aiohttp falls back to its pure-Python parser, which is
somewhat slower. `tr4p doctor` says which one is in use. CI runs the suite
once with `AIOHTTP_NO_EXTENSIONS=1` to keep that path working.

## Run as a service

Sample files are in `packaging/`. Each runs as your own user.

- Linux (systemd): `packaging/tr4p.service`, installation steps in the header.
- macOS (launchd): `packaging/tr4p.plist`, steps in the header.
- Windows (scheduled task at logon): `packaging/tr4p-task.ps1`.
- Any platform with Docker: `docker compose up -d` (restarts on failure).

## Upgrade

```bash
pipx upgrade tr4p            # or: ~/tr4p-venv/bin/pip install --upgrade .
tr4p doctor
```

Back up the state folder first if you care about stored events (the database
is one file). Settings and the secret seed are kept across upgrades.
Restart the service afterwards (`systemctl --user restart tr4p`,
`launchctl kickstart -k gui/$(id -u)/local.tr4p`, or
`Stop-ScheduledTask TR4P; Start-ScheduledTask TR4P`).

## Uninstall

1. Stop and remove the service (see the headers of the files in `packaging/`).
2. `pipx uninstall tr4p`, or delete the virtual environment.
3. Delete the state folder (above) if you do not want the stored events, the
   dashboard password and the secret seed any more. This cannot be undone.
