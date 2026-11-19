#!/bin/sh
# Runs the quickstart inside a bare distro container. Used by CI:
#   docker run --rm -v "$PWD:/src:ro" <image> sh /src/scripts/distro-check.sh
# Installs only what a fresh machine would need, as an ordinary user, in a venv
# (pip refuses system-wide installs on current distros: PEP 668).
set -eu

if [ "$(id -u)" = "0" ]; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv python3-pip >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q python3 python3-pip util-linux >/dev/null
  elif command -v apk >/dev/null 2>&1; then
    apk add --quiet python3 py3-pip
  fi
  useradd -m tr4p 2>/dev/null || adduser -D tr4p
  home=$(su tr4p -c 'echo $HOME')
  cp -r /src "$home/src" && chown -R tr4p "$home/src"
  exec su tr4p -c "sh $home/src/scripts/distro-check.sh"
fi

cd "$HOME/src"
python3 --version
python3 -m venv "$HOME/venv"
. "$HOME/venv/bin/activate"
pip install --quiet .
tr4p --version
tr4p init --yes --mode standalone
tr4p doctor
tr4p run >"$HOME/run.log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
python scripts/smoke http://127.0.0.1:8080
