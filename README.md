# TR4P

A self-hosted deception layer. It detects automated and AI-driven attackers
with several independent signals, then makes attacking a protected site slow
and costly: answers are held back, bait leads nowhere, and confirmed
sessions are quietly moved to a decoy.

> **Authorized use only.** Run TR4P only on infrastructure you own or are
> explicitly authorized to protect. Everything it does stays on your own
> server and in its own responses. It never runs anything on, or sends
> anything harmful to, a visitor's machine.

## Why

Blocking tells an attacker to try something else. TR4P instead lets a
confirmed attacker keep going, slowly, against fake targets, while you watch.
It is one layer. It does not fix vulnerabilities in your application: keep
patching those.

## Threat model

**Built for:** scanners, directory brute-forcing, injection probing,
credential stuffing, and automated agents (including AI-driven ones) that
read pages and follow what they find.

**Assumes** the attacker has read this source code. Canary paths, bait
content, cookie names and fake secrets are derived from a secret seed unique
to each install, and canaries rotate.

**Not a defense against:** a careful human testing by hand at human speed
who never touches a tripwire, denial-of-service floods, or bugs in your
application. See [Limitations](#limitations).

## How it works

1. **Tripwires.** Hidden links, HTML comments, robots.txt entries, hidden
   text addressed to automated agents, and bait files such as `/.env`. No
   person can see or reach them, including people using screen readers.
2. **Scoring.** Each session is scored from independent kinds of evidence.

   | Tier | Needs | What happens |
   | --- | --- | --- |
   | low | any single signal | logged only, never acted on |
   | medium | two independent kinds of evidence | light tarpit (short, capped delays) |
   | high | two kinds including a canary, or three kinds | full tarpit, answers come from the decoy |

   One signal never does more than log, however often it repeats. Sessions
   follow a signed cookie plus a header fingerprint, never an address alone.
   Besides tripwires, payloads and volume, behaviour counts as evidence: a
   steady pace between page requests, many page requests in flight at once,
   retrying a failing path with changed parameters, acting on a discovery
   document, and changing a bait cookie. Behavioural kinds are weak: they add
   to the score but cannot, without a strong kind among them, make the high
   tier. Secrets shown in bait are issued per session, so one that turns up in
   another session links the two as one campaign.
3. **Tarpit.** Answers are held back 1 s, 2 s, 4 s and so on up to a cap,
   sent as a slow drip so the client's own timeout never rescues it.
4. **Cost layers.** Fake directory trees, long pages that burn an automated
   reader's time and context, a fake admin area where each step takes twice
   as long as the last, and secrets that are honeytokens: using one is itself
   a detection. The bait library covers deployment, pipeline, state and
   collection files, status and debug pages, and a made-up script bundle with
   a source map; all of it is generated from your seed and invisible to
   visitors, screen readers and search engines (robots.txt disallows it and
   every bait response says `noindex, nofollow`).
   Automated clients like maps, so the trap also serves made-up discovery
   documents (an agent-style index, an API description, a GraphQL schema, a
   tool listing) that describe an "internal" API existing only as canned
   text. Conventional names such as `/llms.txt` are served only when your own
   site has no such file. **Reading a document is not a signal**; acting on
   what it lists is.
5. **Decoy.** High-tier sessions are answered by an emulated application
   with invented data, on the same address and port. If the decoy is down,
   they get an error page, never your real site. The decoy picks what to
   show from what the session tried (a database console for injection, a
   file manager for path traversal, a customer portal for logins), and keeps
   the same facts throughout. It also shows canned database errors, a partial
   win for a classic injection, and "slow queries" an attacker can time.
6. **Friction.** Now and then a high-tier session meets a canned firewall or
   rate-limit page with a hint that points at an emulated endpoint. Whether
   it does is fixed by the install seed, the session and the request count.
7. **Reports.** Any session can be exported as an incident report (Markdown
   or JSON) with a playbook of what it did, in the dashboard or with
   `tr4p report`. Attacker-supplied text is cleaned and escaped. Figures such
   as held time and bytes sent are measured; the token count is an estimate.

Everything served to attackers is text computed from the seed. Nothing they
send is ever executed, evaluated, or passed to a database, shell or file
system.

## Quickstart

Requires Python 3.10 or newer on Linux, macOS or Windows. To try it with its
built-in site:

```bash
pip install .
tr4p init --yes --mode standalone
tr4p doctor
tr4p run
```

Then open `http://127.0.0.1:8787`, enter the setup code printed by
`tr4p run`, and create the dashboard password. There is no default password.

To protect a real site, run `tr4p init` without `--yes` and answer the
questions, or see the [guidebook](docs/GUIDE.md).

Once the repository is public it can also be installed with
`pipx install git+https://github.com/Wu-Falin/tr4p`. If pip answers
`externally-managed-environment`, use a virtual environment or pipx; if the
`tr4p` command is not found, use `python -m tr4p` (`tr4p doctor` prints the
PATH fix). [docs/INSTALL.md](docs/INSTALL.md) has the support matrix of what
is tested in CI and what is best effort, service files for systemd, launchd
and Windows, and upgrade and uninstall steps.

### Supported platforms

| Tested in CI | Best effort (should work, not run automatically) |
| --- | --- |
| Python 3.10 and 3.13 on Linux x86_64, full suite | Python 3.11, 3.12 and newer than 3.13 |
| Windows Server runner, Python 3.10 and 3.13, full suite | Windows 10 and 11 desktop |
| macOS Apple-silicon runner, Python 3.13, full suite | macOS on Intel; Homebrew Python |
| Quickstart on Ubuntu, Windows and macOS | Other Linux distributions; Linux arm64 native, Raspberry Pi OS |
| Debian 12, Ubuntu 22.04 and 24.04, Fedora 41, Alpine 3.21 (distro Python in a venv) | |
| Docker image, linux/amd64 (full flow); linux/arm64 (built and started under emulation) | |

Python 3.9 and older are refused with a plain message. This is not a promise
that it works everywhere; see [docs/INSTALL.md](docs/INSTALL.md).

### With Docker

```bash
docker compose up -d
docker compose logs main
```

The log shows the setup code. The public listener is on port 8080 and the
dashboard on `http://127.0.0.1:8787`, reachable from that machine only. The
decoy runs in its own container on an internal network with no route to the
outside world; the only thing it shares that network with is the main
service, whose dashboard refuses it. To
protect an existing site:

```bash
TR4P_MODE=proxy TR4P_UPSTREAM=http://your-app:3000 docker compose up -d
```

### Commands

| Command | What it does |
| --- | --- |
| `tr4p init` | create config and secret seed (guided) |
| `tr4p run` | start the trap and the dashboard |
| `tr4p doctor` | check permissions, dashboard exposure, proxy trust, decoy health |
| `tr4p passwd` | set or reset the dashboard password |
| `tr4p canaries` | list the current canary paths |
| `tr4p schema FILE` | give the decoy your table and column names (never data) |
| `tr4p purge --days N` | delete stored events and sessions older than N days |
| `tr4p report ID` | print an incident report for one session (`--format json` for JSON) |

## Tiring levels

A level sets how hard trapped sessions are hit. It never changes who gets
trapped: the score thresholds are separate settings.

| Level | First delay | Longest delay | Medium tier cap | Fake tree depth | Long page | Redirect chance |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 0.5 s | 4 s | 1 s | 2 | 8 KB | 0% |
| 2 | 1 s | 8 s | 1 s | 3 | 16 KB | 0% |
| 3 (default) | 1 s | 16 s | 2 s | 4 | 32 KB | 2% |
| 4 | 2 s | 32 s | 4 s | 6 | 64 KB | 5% |
| 5 | 2 s | 60 s | 8 s | 8 | 128 KB | 10% |

## What it costs to run

Measured with `scripts/benchmark` inside a container limited to 1 CPU and
512 MB of memory:

| Measurement | Result |
| --- | --- |
| Memory when idle (service and decoy together) | 78 MB |
| Memory with 2,000 trapped connections held at once | 123 MB |
| Ordinary visitor served during that flood | 2 ms |
| Ordinary traffic, with the load generator sharing the same CPU | about 2,200 requests/s |

These are single measurements in a development container. Measure on your
own server:

```bash
python scripts/benchmark
```

or under the same limits:

```bash
docker run --rm --cpus 1 --memory 512m --ulimit nofile=8192:8192 --entrypoint python tr4p:local /app/scripts/benchmark
```

Self-protection is built in: held sessions are capped and the oldest dropped,
each trapped session gets two requests at once, memory for held answers is
capped, open connections are capped, idle connections are closed and stalled
uploads cut off. The protected site's own connection is released before a
hold begins.

## Limitations

Read these before relying on it.

- **It raises cost; it does not stop a determined attacker.** A skilled
  person can recognise a deception layer.
- **In proxy mode the decoy is a profile, not a clone.** It imitates a
  generic app, a PHP site, a WordPress blog or an API. Someone who knows your
  real site will notice the difference. In standalone mode the switch is
  seamless.
- **Process isolation is not a sandbox.** Installed with pip, the decoy is a
  separate process with an empty environment and contains no code that opens
  outbound connections, but nothing at operating-system level stops it. With
  Docker Compose it runs in its own container on a network with no route
  out. Use the container setup where that matters.
- **The cookie hash chain does not stop replay by itself.** The server's own
  memory is what defeats replaying an older cookie. The chain makes the
  tarpit phase unforgeable and lets a restarted server resume at the phase a
  cookie proves.
- **Changing identity resets detection.** A client that discards cookies and
  changes its header fingerprint starts from zero. Signals build up again
  quickly, but nothing is remembered by address alone, on purpose.
- **A weakly trapped client can shed the light tarpit** by changing cookie
  identity, because evidence carried over by fingerprint counts for less.
  That is the price of protecting look-alike visitors.
- **Look-alike visitors.** Someone sharing both address and exact browser
  fingerprint with a trapped cookie-less client can be slowed, or see one
  decoy page, before getting a session of their own.
- **Behavioural kinds can misread scripts.** A monitoring script with a
  steady pace looks machine-like. It still only reaches the low tier, because
  one weak kind never does more than log. Check `python scripts/simulate`
  after changing weights or thresholds: it replays scripted visitors,
  including ordinary ones, and fails if any ends in the wrong tier.
- **Secret-to-session linking is memory-only.** After a restart a returning
  secret is still recognised as planted, but the link to the session it was
  issued to is lost. The decoy shows install-wide secrets, not per-session
  ones.
- **The new signal weights are tuned judgments**, not measurements. The
  scripted-visitor scorecard (`python scripts/simulate`) guards them, and it
  is only as good as the visitors it describes.
- **Themes, block pages and canned errors are emulation.** A knowledgeable
  attacker may notice that an error page is too convenient.
- **The token figure is an estimate** (bytes sent divided by 4). Held time
  and bytes are measured.
- **False positives are possible.** A misbehaving but harmless crawler or
  browsing assistant can end up in the tarpit. Use the release button, the
  whitelist, and the thresholds.
- **Hidden instructions are a tripwire, not a shield.** They show that
  something read text no person could see. They stop nobody.
- **A tarpit costs time per connection.** An attacker with many addresses
  pays less per request.
- **The blocklist file lists addresses.** An address can be shared by an
  office, a mobile carrier or a VPN.
- **Measurements were taken in a development container**, not on your
  hardware.
- **It stores client addresses** of flagged sessions. See privacy and
  retention in the guidebook.

## Not built yet

- Encryption of the seed file at rest. It is protected by file permissions
  only.
- The text-only mischief pack (taunting fake rows and messages).
- Log replay: measuring offline how many real visitors a configuration
  would have flagged.
- A dashboard for several instances. The API is ready for one; only the
  single-instance view exists.
- TLS fingerprinting. TR4P sits behind your TLS proxy and never sees the
  handshake; fingerprints come from headers and behaviour.
- Decoy profiles backed by real application stacks. The decoy is emulated.

Alert delivery was tested against local stand-in servers only, not against
the live Slack, Discord, ntfy or mail services.

## Documentation

- [Installing, upgrading, supported platforms](docs/INSTALL.md): what is
  tested in CI and what is best effort, service files, uninstall.
- [Defender guidebook](docs/GUIDE.md): deployment, TLS proxy setup, tuning,
  false positives, blocklist, alerts, backup, upgrade, privacy.
- [Architecture](ARCHITECTURE.md): how the pieces fit and why.
- [Security policy](SECURITY.md) and [contributing](CONTRIBUTING.md).

## Development

```bash
pip install -e ".[dev]"
python -m pytest
python scripts/audit-footprints
```

## License

MIT. See [LICENSE](LICENSE).
