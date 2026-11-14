# Defender guidebook

Use TR4P only on infrastructure you own or are explicitly authorized to
protect.

Settings live in `config.json` in the home directory (`tr4p --home DIR`, the
`TR4P_HOME` variable, or the per-user default printed by `tr4p init`). Edit
the file, run `tr4p doctor`, then restart. Tiring level, delays, thresholds,
fake-tree depth and redirect chance can also be changed live in the
dashboard.

## 1. Deployment modes

### In front of your site (reverse proxy)

```
visitor -> your TLS proxy -> TR4P (port 8080) -> your application
```

```bash
tr4p init --mode proxy --upstream http://127.0.0.1:3000
```

Ordinary visitors are passed straight through. Their pages get hidden
tripwires added; if that ever fails, the original page is served. Keep your
application reachable only through TR4P, otherwise an attacker simply goes
around it.

### Standalone

```bash
tr4p init --mode standalone
```

TR4P serves a small built-in site and nothing real. Useful on a spare
address or hostname as an early-warning sensor.

### Decoy profile

Pick what resembles your site most: `generic`, `php`, `wordpress` or `api`
(`tr4p init --profile php`). Optionally give the decoy the shape of your
database, never its contents:

```bash
mysqldump --no-data yourdb > schema-only.sql
tr4p schema schema-only.sql
```

Only table names, column names and types are kept. A file containing data
rows is refused.

## 2. TLS proxy and trusted proxy headers

TR4P speaks plain HTTP. Terminate TLS in front of it and tell TR4P which
proxy to believe about client addresses. Without that, every visitor looks
like the proxy and is treated as one client.

nginx:

```nginx
server {
    listen 443 ssl;
    server_name shop.example;
    # ssl_certificate ...; ssl_certificate_key ...;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;   # overwrite, do not append
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 120s;                         # longer than your longest delay
        proxy_buffering off;                             # let the slow drip through
    }
}
```

Caddy:

```
shop.example {
    reverse_proxy 127.0.0.1:8080 {
        flush_interval -1
    }
}
```

Then in `config.json`:

```json
"public": {
  "host": "127.0.0.1",
  "trusted_proxies": ["127.0.0.1"],
  "client_ip_header": "X-Forwarded-For"
}
```

- List only your own proxy. Never a whole range you do not control: anyone
  inside it could fake their address. `tr4p doctor` refuses `0.0.0.0/0`.
- Behind a CDN, list the CDN's published ranges and set `client_ip_header`
  to the header it documents.
- Set the proxy's read timeout above the longest tarpit delay (60 s at
  level 5), or the proxy will cut held connections first.

## 3. Tuning

| Setting | Where | Meaning |
| --- | --- | --- |
| Tiring level 1-5 | dashboard | how long trapped sessions wait, how deep the fake tree goes |
| `detection.medium_threshold` (40) | dashboard, config | score for the light tarpit |
| `detection.trap_threshold` (70) | dashboard, config | score for the full tarpit and decoy |
| `detection.weights` | config | weight of each signal type |
| `tarpit.max_sessions` (2000) | dashboard, config | sessions held at once; oldest dropped beyond |
| `canary.rotation_hours` (24) | config | how often canary paths change |
| `inject.enabled` | config | add hidden tripwires to your pages |
| `decoy.enabled` | config | off keeps high-tier sessions on the real site, tarpit only |

Start at level 3 with default thresholds and watch the dashboard for a week
before changing anything. Raise the level if attackers are not slowed
enough. Raise the thresholds if harmless clients are being flagged.

## 4. False positives

Detection is built to avoid them: a single signal only logs, tripwires are
invisible to people and screen readers, robots.txt keeps polite crawlers
away, and verified search engine crawlers are exempt. They can still happen.

- **Release.** In the dashboard, open the session's timeline to see why it
  was flagged, then press Release. The session goes back to your real site,
  its decoy state is wiped and its blocklist entry removed.
- **Whitelist** your own scanners, monitoring and testing addresses:
  `"whitelist": ["192.0.2.10", "198.51.100.0/24"]`. Whitelisted addresses
  bypass detection completely.
- **Expiry.** A flagged session with no new signal for 24 hours starts over
  (`session.trap_ttl_hours`).
- **Typical causes:** an in-house crawler that ignores robots.txt, a
  monitoring script requesting odd paths, a browsing assistant that follows
  hidden text. Whitelist the first two.

## 5. Blocklist export

`blocklist.txt` in the home directory lists the addresses of clients
confirmed in the high tier, one per line with its expiry as a comment. It is
rewritten as entries are added and expire (24 hours by default,
`block.ttl_hours`).

**An address can be shared by many people**: offices, mobile carriers, VPNs.
Blocking by address alone can lock them out too. Inside TR4P an entry is
always address plus header fingerprint; the file cannot express that.

nginx:

```bash
awk '!/^#/ && NF {print "deny " $1 ";"}' blocklist.txt > /etc/nginx/tr4p-deny.conf
nginx -s reload
```

with `include /etc/nginx/tr4p-deny.conf;` in the server block.

nftables:

```bash
nft add set inet filter tr4p '{ type ipv4_addr; flags timeout; }'
awk '!/^#/ && NF {print $1}' blocklist.txt | while read a; do
  nft add element inet filter tr4p "{ $a timeout 24h }"
done
```

fail2ban, using a jail you already have:

```bash
awk '!/^#/ && NF {print $1}' blocklist.txt | xargs -r -n1 fail2ban-client set YOURJAIL banip
```

Run these from a timer. To have TR4P itself refuse listed clients, set
`"block": {"enforce": true}`. It is off by default because holding an
attacker in the tarpit costs them more and tells them less.

## 6. Alerts

Alerts fire for the high tier by default (`alerts.min_tier`), for honeytoken
use and for sensitive decoy content being reached. They are de-duplicated
for ten minutes per session and limited to six a minute; held-back alerts
are counted in the next one. Attacker-supplied text is cleaned first.

Webhook (generic JSON with both `text` and `content` fields):

```json
"alerts": { "webhook_url": "https://hooks.example.com/services/XXXX" }
```

- **Slack** and **Discord** incoming webhooks accept this as is.
- **ntfy**: use the topic URL. The message body is the JSON document.
- Private and loopback targets are refused unless you set
  `"webhook_allow_private": true`. Redirects are never followed.

E-mail:

```json
"alerts": {
  "email_to": ["soc@example.com"],
  "email_from": "trap@example.com",
  "smtp_host": "mail.example.com",
  "smtp_port": 587,
  "smtp_user": "trap",
  "smtp_security": "starttls"
}
```

The SMTP password is never stored in `config.json`. Set the
`TR4P_SMTP_PASSWORD` environment variable, or put the password in a file
named `smtp.secret` in the home directory with owner-only permissions.

## 7. The dashboard

- It listens on `127.0.0.1` only. From another machine, use an SSH tunnel:
  `ssh -L 8787:127.0.0.1:8787 your-server`.
- No default password. First run asks for a one-time code printed on the
  server console. `tr4p passwd` resets the password.
- Do not put it on the public listener or publish its port.

## 8. Backing up the seed

`secret.key` in the home directory is what makes your install unique:
canary paths, session cookies, fake secrets and the decoy all derive from it.

- Back it up somewhere private, together with `config.json`.
- If it is lost, run `tr4p init --force`: you get a new seed, new canaries,
  and existing trapped sessions are forgotten. Nothing else breaks.
- If it leaks, an attacker can compute your canary paths and avoid them. Run
  `tr4p init --force` to replace it.
- `events.db` holds the event log and can be recreated empty.

## 9. Upgrading

```bash
pip install --upgrade .        # from an updated checkout
tr4p doctor
```

then restart. With Docker: `docker compose up -d --build`. Config and seed
live in the home directory or the `data` volume and are kept. Settings added
by a new version take their defaults.

## 10. Privacy and retention

TR4P writes nothing about ordinary visitors to disk. For **flagged**
sessions it stores the client address, user agent, requested paths and
signals, because that is the evidence. Client addresses can be personal
data.

- Events and sessions older than `storage.retention_days` (30) are deleted
  automatically.
- Delete on demand: `tr4p purge --days 7` or `tr4p purge --all`.
- The session cookie is set for all visitors by default so that being
  flagged does not change what a client sees. Set
  `"session": {"cookie_mode": "on_signal"}` to set it only after a first
  signal. Mention the cookie in your privacy notice as a security measure.
- The blocklist file and alerts contain client addresses too. Treat them
  accordingly.

## 11. Checking it works

```bash
tr4p doctor
python scripts/smoke http://127.0.0.1:8080     # standalone mode only
python scripts/benchmark
```

`tr4p canaries` lists the current canary paths. Request one with a command
line client and watch the session appear in the dashboard.
