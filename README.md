# TR4P

A self-hosted deception layer that detects automated and AI-driven attackers
and makes attacking a protected site slow and costly.

> **Authorized use only.** Run TR4P only on infrastructure you own or are
> explicitly authorized to protect. Everything it does stays on your own
> server and in its own responses. It never runs anything on, or sends
> anything harmful to, a visitor's machine.

## Status

Work in progress. This is phase 1 of 4.

| Phase | What | State |
| --- | --- | --- |
| 1 | Detection engine, canaries, event log, dashboard | done |
| 2 | Tarpit and other cost layers | not started |
| 3 | Mirrored decoy | not started |
| 4 | Docker, benchmarks, full documentation | not started |

Right now TR4P **detects and records**. It does not slow down or reroute
anyone yet.

## What it does today

- Sits in front of your site as a reverse proxy, or runs standalone.
- Plants tripwires no person can see or reach: hidden links, HTML comments,
  robots.txt entries, hidden text addressed to automated agents, and bait
  files such as `/.env`. All of it is derived from a per-install secret, so
  no two installs look alike, and it rotates on a schedule.
- Scores each session from independent signals and sorts it into a tier.
- Shows live activity in a local dashboard.

### How a session gets flagged

| Tier | Needs | Meaning |
| --- | --- | --- |
| low | any single signal | logged only, never acted on |
| medium | two independent kinds of evidence | suspicious |
| high | two kinds including a canary, or three kinds | confident |

One signal never does more than log, however often it repeats. Signals that
come from the same behaviour (for example speed and a burst of missing pages)
count as one kind of evidence. Sessions follow a signed cookie plus a header
fingerprint, never an IP address alone, so people behind one NAT address are
not lumped together. Verified search engine crawlers are exempt, and any
session can be released from the dashboard with one click.

## Honest limits

- A skilled attacker can still recognise a deception layer. The goal is to
  raise their cost, not to be invisible.
- Hidden instructions are a tripwire, not a shield. They reveal that
  something read text no person could see. They stop nobody.
- TR4P does not fix vulnerabilities in your application. Keep patching it.
  This is one layer, not the whole defense.
- An attacker who changes fingerprint and discards cookies starts detection
  from zero. Signals build up again quickly, but there is no memory of them.
- False positives are possible. See the tiers above, and use the whitelist
  for your own testing addresses.

## Quick start

Requires Python 3.10 or newer on Linux, macOS or Windows.

```bash
pip install .
tr4p init
tr4p run
```

`tr4p init` asks a few questions and writes the config and a secret seed to
a private directory outside this repository. `tr4p run` starts two listeners:

- the public one, which you put behind your TLS proxy;
- the dashboard, on `127.0.0.1` only. It has no default password: you create
  one during `tr4p init`, or with a one-time code printed by `tr4p run`.

Other commands: `tr4p canaries` lists the current canary paths, and
`tr4p passwd` resets the dashboard password.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
python scripts/audit-footprints
```

## License

MIT. See [LICENSE](LICENSE).
