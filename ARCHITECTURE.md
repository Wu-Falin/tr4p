# Architecture

## The shape of it

```
                      +--------------------------- main process ---------------------------+
visitor --> TLS proxy | public listener --> engine (signals, score, tier, tarpit phase)    |
                      |      |                 |                                           |
                      |      |  none/low/medium|            high                           |
                      |      v                 v              v                            |
                      |  protected site    tarpit hold    decoy link --(loopback or        |
                      |  (reverse proxy)   (slow drip)                  internal network)--+--> decoy process
                      |                                                                    |    (emulation only)
                      |  canary paths --> maze (bait, burn pages, fake admin area)         |
                      |  events --> SQLite, live feed, alerts     dashboard (loopback)     |
                      +--------------------------------------------------------------------+
```

Two listeners, two ports: the public one, and the dashboard on loopback.
One optional child: the decoy.

## Modules

| Module | Job |
| --- | --- |
| `seed` | install secret; derives every per-install value with HMAC |
| `config`, `levels` | validated settings, tiring-level presets |
| `canary`, `inject`, `honeytoken` | rotating hidden paths, tripwires added to pages, fake secrets |
| `clients`, `payloads` | classify user agents and headers, recognise attack payloads |
| `scoring` | weights, evidence groups, tiers |
| `session` | bounded in-memory session table |
| `engine` | turns requests into signals, tiers, delays; no HTTP or storage code |
| `tarpit` | holds answers back cheaply; caps and adaptive bumps |
| `maze`, `loot` | everything served under canary paths |
| `blocklist`, `alerts` | expiring high-tier list, webhook and e-mail |
| `proxy`, `public` | reverse proxy and the public listener |
| `decoy/`, `decoylink` | the emulated application and the link to its process |
| `store`, `bus` | SQLite event log, live fan-out |
| `dashboard/` | local admin interface |
| `doctor`, `schema`, `cli`, `runtime` | checks, schema import, commands, wiring |

## Design decisions

**Assume the source is public.** Nothing relies on the attacker not knowing
how it works. What they cannot know is the seed. Canary paths, cookie name,
banner, site name and fake secrets all come from it, and canaries rotate
daily while rotated-out ones stay armed for a week.

**Being sure.** Signal types that stem from one behaviour share an evidence
group (speed, a burst of missing pages and a login burst are one group).
A group counts once. One group only logs. Medium needs two groups. High
needs a canary-type signal among them, or three groups. A honeytoken coming
back is sufficient alone, because nobody holds one without having read
hidden bait.

**Identity is cookie plus fingerprint, never address alone.** Cookie-less
clients are grouped by address and header fingerprint together. A trapped
session's evidence carries over to a new cookie from the same group, at
reduced weight and never into the high tier by itself, so an attacker cannot
launder state with a fresh cookie and a look-alike visitor is not dragged
into the decoy.

**The session cookie is the head of a hash chain.**
`link(0) = HMAC(key, id)`, `link(n) = HMAC(key, link(n-1) | id | n)`, and
the cookie carries `id | n | truncated link(n)`, where `n` is the tarpit
phase. Only the server can make the next link. Server memory remains the
authority against replay; the chain makes the phase unforgeable and lets a
restarted server resume where a cookie proves the session was.

**Fail open for visitors, fail closed for attackers.** Tripwire injection
never blocks a page: any error serves the original. The decoy path is the
opposite: if the decoy is unavailable, a high-tier session gets an error
page and is never passed to the real site.

**Holding connections must be cheap.** A hold is an idle socket and a
timer. The protected site's connection is released before the hold starts.
Held sessions, per-session concurrency, buffered bytes and open connections
are all capped; past a cap, the oldest trapped connection is dropped.

**Emulation only.** Bait, burn pages, the fake admin area, its "query
console" and the decoy are text computed from the seed and the path. Input
is compared with a few fixed shapes and echoed back escaped. There is no
database, interpreter, shell or outbound fetch behind any of it.

**Stateless where possible.** Canary pages keep nothing: the same path
always produces the same page. Fake admin steps are tied to signed,
time-stamped tokens rather than stored progress. Dynamic pages vary request
ids and formatting per answer, not facts.

**Decoy isolation.** As a child process the decoy gets an empty environment,
an empty directory, a seed derived for it alone and a random key; it never
sees the install secret, the configuration or the upstream address. In the
container setup it is a separate service on an internal network with no
route out, reading one hand-over file from a read-only volume.

**The dashboard is an attack surface.** Loopback by default, its own port,
no default credentials, a console-only setup code, a Host allow-list against
DNS rebinding, same-origin and custom-header checks plus a per-session token
on every change, rate-limited logins, a strict content security policy, and
attacker-supplied text rendered only as text.

**Privacy by default.** Nothing about clean traffic is stored. Flagged
sessions are kept for a set number of days and can be purged.

## What is deliberately not here

- No code that runs on, or is aimed at, a visitor's machine.
- No blocking by address alone, and no blocking at all unless switched on.
- No TLS termination: use a proper TLS proxy.
- No copy of real data. The schema import keeps names and types only.

## Multi-instance later

Every dashboard API answer carries the instance id, and status, events and
sessions are plain JSON over `/api/v1/`. A central view can poll several
instances without changes on this side. Only single-instance is built.
