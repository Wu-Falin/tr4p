#!/bin/sh
# Container entry point for both services.
#   decoy          run the decoy; it reads only the hand-over file
#   anything else  is passed to the tr4p command (default: run)
set -eu

if [ "${1:-run}" = "decoy" ]; then
    exec python -m tr4p.decoy --settings /handoff/decoy.json --host 0.0.0.0 --port 8081
fi

first_start() {
    tr4p init --yes "$@" \
        --profile "${TR4P_PROFILE:-generic}" \
        --public-host 0.0.0.0 --public-port 8080 \
        --dashboard-host 0.0.0.0 --dashboard-port 8787 \
        --decoy-url http://decoy:8081 --decoy-handoff /handoff >/dev/null
}

if [ ! -f "$TR4P_HOME/config.json" ]; then
    # Config and seed are created inside the volume, never baked into the image.
    if [ "${TR4P_MODE:-standalone}" = "proxy" ]; then
        first_start --mode proxy --upstream "${TR4P_UPSTREAM:?set TR4P_UPSTREAM to the site to protect}"
    else
        first_start --mode standalone
    fi
fi

exec tr4p "$@"
