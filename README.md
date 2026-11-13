# TR4P

A self-hosted deception layer that detects automated and AI-driven attackers
and makes attacking a protected site slow and costly.

> **Authorized use only.** Run TR4P only on infrastructure you own or are
> explicitly authorized to protect. Everything it does stays on your own
> server and in its own responses. It never runs anything on, or sends
> anything harmful to, a visitor's machine.

## Status

Work in progress.

| Phase | What | State |
| --- | --- | --- |
| 1 | Detection engine, canaries, event log, dashboard | done |
| 2a | Escalating tarpit, session caps, tiring levels | done |
| 2b | Token-burn pages, rabbit hole, fake kill chain, alerts | done |
| 3 | Mirrored decoy | not started |
| 4 | Docker, benchmarks, full documentation | not started |

Right now TR4P **detects, records, slows down and wastes effort** inside its
own canary paths. It does not reroute anyone to a full decoy site yet.

## What it does today

- Sits in front of your site as a reverse proxy, or runs standalone.
- Plants tripwires no person can see or reach: hidden links, HTML comments,
  robots.txt entries, hidden text addressed to automated agents, and bait
  files such as `/.env`. All of it is derived from a per-install secret, so
  no two installs look alike, and it rotates on a schedule.
- Scores each session from independent signals and sorts it into a tier.
- Holds back answers to trapped sessions, longer each time.
- Shows live activity in a local dashboard, with a per-session timeline.

### How a session gets flagged

| Tier | Needs | What happens |
| --- | --- | --- |
| low | any single signal | logged only, never acted on |
| medium | two independent kinds of evidence | light tarpit (short, capped delays; page assets are spared) |
| high | two kinds including a canary, or three kinds | full tarpit |

One signal never does more than log, however often it repeats. Signals that
come from the same behaviour (for example speed and a burst of missing pages)
count as one kind of evidence. Sessions follow a signed cookie plus a header
fingerprint, never an IP address alone, so people behind one NAT address are
not lumped together. Verified search engine crawlers are exempt, and any
session can be released from the dashboard with one click.

Evidence does not last forever. A flagged session with no new signal for 24
hours starts over. Evidence that reached a session only because it shares an
address and header fingerprint with a trapped one counts for less, is
forgotten after 30 minutes, and can never put that session in the high tier
by itself.

### The tarpit

Answers to trapped sessions are held back: 1 s, 2 s, 4 s and so on up to a
cap, with some randomness so the pattern is not a fixed number. Longer holds
are sent as a slow drip, a small piece every couple of seconds with the last
piece at the very end, so the client's own timeout never rescues it.

Clients that pile up parallel requests or hang up early move through the
delays faster. That only ever applies to sessions that are already trapped.

Five tiring levels set how long the delays get:

| Level | First delay | Longest delay | Longest delay, medium tier |
| --- | --- | --- | --- |
| 1 | 0.5 s | 4 s | 1 s |
| 2 | 1 s | 8 s | 1 s |
| 3 (default) | 1 s | 16 s | 2 s |
| 4 | 2 s | 32 s | 4 s |
| 5 | 2 s | 60 s | 8 s |

A level changes how hard trapped sessions are hit. It never changes who gets
trapped: the score thresholds are separate settings.

### Cost layers

All of this lives under the hidden canary paths, so ordinary visitors never
reach it. Every page is computed from the install seed and the path, nothing
is stored per page, and every answer has a hard size cap.

- **Rabbit hole.** Fake directory listings lead to more listings and files,
  down to a configurable depth.
- **Token-burn pages.** Long, plausible logs and wiki pages that cost an
  automated reader time and context. Trapped sessions get the long version.
- **Fake kill chain.** Bait files point to a fake admin area. The planted
  credentials "work", and so does a classic injection string. Each step
  after that takes twice as long as the one before. It is an emulation:
  nothing an attacker sends is ever executed, evaluated, or passed to a
  database, shell or file system. The "query console" matches a few fixed
  shapes and prints canned text.
- **Poisoned loot.** Every secret in bait is a honeytoken made up at run
  time. Using one anywhere puts the session in the high tier at once.
- **Mutation.** Dynamic pages vary request ids, key order and formatting on
  every answer, so automation cannot cache them. Facts stay the same.
- **Teleport.** High-tier requests are sometimes redirected into an endless
  built-in maze. Outside targets can be configured; the list is empty by
  default.

The tiring level also sets rabbit-hole depth, long-page size and redirect
chance. Depth and redirect chance can be changed in the dashboard.

### Blocklist

Clients confirmed in the high tier are listed as address plus header
fingerprint, never either alone. Entries expire after 24 hours, and
releasing a session removes its entry. Whitelisted addresses and verified
crawlers are never listed.

- Refusing listed clients (`block.enforce`) is off by default: holding them
  in the tarpit costs them more and tells them less.
- `blocklist.txt` in the home directory lists the addresses for tools such
  as a firewall. **An address can be shared by many people** (offices,
  mobile carriers, VPNs). Blocking by address alone can lock them out too.

### Alerts

Optional webhook (generic JSON) and e-mail, each off until configured.

- Webhook targets must be http(s). Private and loopback addresses are
  refused unless `alerts.webhook_allow_private` is set, and the check is made
  on the address actually connected to. Redirects are not followed.
- Alerts are de-duplicated and rate limited; held-back ones are counted.
- Attacker-supplied text is cleaned before it is sent anywhere.
- The SMTP password is never in the config file. Set `TR4P_SMTP_PASSWORD`
  or put it in `smtp.secret` in the home directory.

### Staying cheap for the defender

A held connection costs an idle socket and a timer. The protected site's own
connection is released before a hold starts, so trapped clients cannot pin
it. On top of that:

- sessions held at once are capped (2,000 by default); past the cap the
  oldest is dropped;
- each trapped session may run two requests at once, with a short queue;
- memory spent on held answers is capped;
- open connections are capped, idle ones are closed, stalled uploads are
  cut off.

Measured in a test that ships with the code (`tests/test_flood.py`): 2,000
connections held at once used 83 MB in total, and an ordinary visitor was
still served in under 20 ms. That is one measurement on a development
container, not a promise for your hardware.

## Honest limits

- A skilled attacker can still recognise a deception layer. The goal is to
  raise their cost, not to be invisible.
- Hidden instructions are a tripwire, not a shield. They reveal that
  something read text no person could see. They stop nobody.
- TR4P does not fix vulnerabilities in your application. Keep patching it.
  This is one layer, not the whole defense.
- An attacker who changes fingerprint and discards cookies starts detection
  from zero. Signals build up again quickly, but there is no memory of them.
- A tarpit costs an attacker time per connection. One with many addresses
  and many connections pays less per request. It raises cost; it does not
  stop a determined, well-resourced attacker.
- A visitor who shares both address and exact browser fingerprint with a
  trapped cookie-less client can be slowed for one request before getting a
  session of their own.
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
