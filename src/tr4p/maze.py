"""Cost layers inside canary territory: rabbit hole, token-burn pages, the
fake kill chain and the self-hosted maze.

Everything here is an emulation that produces text. Hard rules:

* Nothing an attacker sends is ever executed, evaluated, used as a file name
  or passed to a database. Input is only matched against a few fixed shapes
  and echoed back escaped. The "SQL console" has no database behind it.
* Pages are a pure function of the install seed and the path, so nothing is
  stored per page and the same path always tells the same story.
* Every answer has a hard size cap.

Mutation changes how an answer looks (request ids, key order, formatting),
never what it says, so a session sees consistent facts.
"""

from __future__ import annotations

import json
import random
import re
import secrets
import time
from html import escape
from typing import Any, Callable
from urllib.parse import parse_qs, parse_qsl

from tr4p.canary import Canaries
from tr4p.config import Config
from tr4p.honeytoken import Honeytokens
from tr4p.loot import Loot, LootFactory
from tr4p.payloads import find_payload
from tr4p.persona import Persona
from tr4p.seed import Seed

HARD_PAGE_CAP = 512 * 1024
SMALL_PAGE = 4096
MAX_STAGE = 9
STAGE_SECONDS = 15.0
STAGE_SECONDS_CAP = 600.0
TOKEN_LIFETIME = 86400.0
MAX_HOPS = 3

_STAGES = (
    "Backup export", "Database snapshot", "Role sync", "Key vault unseal",
    "Replication catch-up", "Audit archive", "Storage rebalance",
    "Tenant migration", "Ledger reconcile", "Maintenance window",
)
_STAGE_SECRETS = ("api_key", "db_password", "deploy_token", "jwt_secret", "smtp_password")
_USERS = ("anna.keller", "david.novak", "maria.silva", "ops-batch", "svc-report", "lena.meyer")
_LOG_LINES = (
    "INFO  auth: login ok user={user} ip={ip} session={hex}",
    "WARN  auth: {n} failed logins for user={user} ip={ip}",
    "INFO  export: job {n} finished rows={big} file={dir}export-{n}.csv",
    "DEBUG db: slow query ({ms} ms) SELECT * FROM orders WHERE customer_id={big}",
    "ERROR mailer: smtp auth failed for noreply, retry in {n}s",
    "INFO  cron: nightly sync started batch={hex}",
    "WARN  storage: volume {dir} at {n}% capacity",
    "INFO  api: key rotated for client={user} previous key archived in {dir}keys-{n}.bak",
    "DEBUG cache: evicted {big} entries in {ms} ms",
)
_WORDS = (
    "the", "deployment", "requires", "manual", "review", "before", "each", "release",
    "legacy", "billing", "service", "still", "reads", "from", "old", "replica", "and",
    "must", "be", "migrated", "access", "is", "granted", "through", "internal", "portal",
    "see", "runbook", "for", "rollback", "steps", "credentials", "are", "stored", "in",
    "vault", "export", "jobs", "run", "nightly", "team", "owns", "this", "component",
)
_SHOW_TABLES = re.compile(r"^\s*show\s+tables\b", re.IGNORECASE)
_SELECT_USERS = re.compile(r"^\s*select\b.{1,200}\bfrom\s+`?users`?\b", re.IGNORECASE | re.DOTALL)
_SELECT_VERSION = re.compile(r"^\s*select\s+(?:@@version|version\(\))", re.IGNORECASE)
_TABLE_NAME = re.compile(r"\bfrom\s+`?([A-Za-z_][A-Za-z0-9_]{0,31})`?", re.IGNORECASE)
_NODE = re.compile(r"[0-9a-f]{8}")


class Maze:
    def __init__(
        self,
        seed: Seed,
        config: Config,
        canaries: Canaries,
        honeytokens: Honeytokens,
        persona: Persona,
        loot: LootFactory,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._seed = seed
        self._config = config
        self._canaries = canaries
        self._tokens = honeytokens
        self._persona = persona
        self._loot = loot
        self._clock = clock
        self._random = random.Random()
        loot.admin_path = self.admin_path

    # ------------------------------------------------------------------ entry

    def admin_path(self) -> str:
        return f"/{self._canaries.current().segments['comment']}/admin/"

    def teleport_target(self) -> str:
        """Where a teleported request is sent: an outside target if the
        defender configured any, otherwise a node of the built-in maze."""
        external = self._config.maze.external_targets
        if external:
            return self._random.choice(external)
        segment = self._canaries.current().segments["robots"]
        return f"/{segment}/m/{self._random.getrandbits(32):08x}"

    def respond(self, method: str, path: str, query: str, body: bytes | None,
                host: str, session_key: str, trapped: bool) -> Loot | None:
        """Answer a request inside canary territory. None means "forbidden"."""
        segment, _, rest = path[1:].partition("/")
        current = self._canaries.current()
        if path == current.instruction_path:
            return self._vary(self._loot.agent_notice(current))
        if rest == "admin" or rest.startswith("admin/"):
            return self._admin(segment, rest[5:].strip("/"), method, query, body, session_key)
        if rest.startswith("m/"):
            return self._node(segment, rest[2:].strip("/"), query, trapped)
        if path.lower().endswith(".log"):
            size = self._config.maze.burn_bytes if trapped else SMALL_PAGE
            return Loot(200, self._plain_type(), self._burn_log(path, f"/{segment}/", size), True)
        depth = len([part for part in rest.split("/") if part])
        return self._loot.render(path, host, allow_dirs=depth < self._config.maze.rabbit_depth)

    # ------------------------------------------------------------ token burn

    def _plain_type(self) -> str:
        return "text/plain" if self._persona.family == "apache" else "application/octet-stream"

    def _burn_log(self, path: str, directory: str, size: int) -> bytes:
        """A long, plausible application log. Reading it costs time and
        context; the few "interesting" lines in it are poisoned."""
        size = max(256, min(size, HARD_PAGE_CAP))
        rng = self._seed.rng("burn", path)
        stamp = 1_735_689_600 + rng.randrange(0, 300 * 86400)
        lines: list[str] = []
        total = 0
        while total < size:
            stamp += rng.randrange(1, 90)
            if rng.randrange(70) == 0:
                text = (f"DEBUG config: reloaded, api key {self._tokens.value('api_key')} "
                        f"admin console at {self.admin_path()}")
            else:
                text = rng.choice(_LOG_LINES).format(
                    user=rng.choice(_USERS), ip=f"203.0.113.{rng.randrange(1, 255)}",
                    hex=f"{rng.getrandbits(32):08x}", n=rng.randrange(2, 99),
                    big=rng.randrange(1000, 999999), ms=rng.randrange(200, 9000), dir=directory,
                )
            line = time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime(stamp)) + text
            lines.append(line)
            total += len(line) + 1
        return ("\n".join(lines) + "\n").encode("ascii", "replace")[:size]

    def _prose(self, rng: random.Random, size: int) -> str:
        sentences: list[str] = []
        total = 0
        while total < size:
            words = [rng.choice(_WORDS) for _ in range(rng.randrange(8, 18))]
            sentence = " ".join(words).capitalize() + "."
            sentences.append(sentence)
            total += len(sentence) + 1
        return " ".join(sentences)

    # ------------------------------------------------------------------ maze

    def _node(self, segment: str, name: str, query: str, trapped: bool) -> Loot | None:
        """One page of the endless maze. Its content and links follow from
        its name alone."""
        if not _NODE.fullmatch(name):
            return None
        rng = self._seed.rng("node", name)
        links = [f"{rng.getrandbits(32):08x}" for _ in range(rng.randrange(5, 9))]
        hops = _small_int(dict(parse_qsl(query)).get("h", "0"))
        if int(name, 16) % 4 == 0 and hops < MAX_HOPS:
            return Loot(302, "text/html", b"", location=f"/{segment}/m/{links[0]}?h={hops + 1}")
        size = self._config.maze.burn_bytes if trapped else SMALL_PAGE
        title = f"Internal wiki / {rng.choice(_STAGES)} / {name[:4]}"
        paragraphs = "".join(
            f"<p>{escape(self._prose(rng, 600))}</p>\n" for _ in range(max(1, size // 700))
        )
        nav = "".join(f'<li><a href="/{segment}/m/{link}">Page {link[:6]}</a></li>' for link in links)
        return self._vary(self._page(title, f"{paragraphs}<h2>Related</h2><ul>{nav}</ul>"))

    # ------------------------------------------------------------ kill chain

    def _token(self, session_key: str, stage: int, issued: float) -> str:
        stamp = int(issued)
        return f"{stamp:x}-{self._seed.hex('stage', session_key, stage, stamp, length=20)}"

    def _token_time(self, session_key: str, stage: int, token: str) -> float | None:
        """When a stage token was issued, or None if it is not valid."""
        stamp_text, _, mac = token.partition("-")
        try:
            stamp = int(stamp_text, 16)
        except ValueError:
            return None
        expected = self._seed.hex("stage", session_key, stage, stamp, length=20)
        now = self._clock()
        if not secrets.compare_digest(mac, expected) or not -5 <= now - stamp <= TOKEN_LIFETIME:
            return None
        return float(stamp)

    def _login_ok(self, body: bytes | None) -> bool:
        """The fake vulnerability: planted credentials "work", and so does a
        classic injection string. Nothing is checked against anything real."""
        if not body:
            return False
        text = body.decode("utf-8", "replace")
        fields = parse_qs(text, keep_blank_values=True)
        password = "".join(fields.get("password", [""]))
        if password and password == self._tokens.value("admin_password"):
            return True
        return find_payload(text) == "sqli"

    def _admin(self, segment: str, sub: str, method: str, query: str,
               body: bytes | None, session_key: str) -> Loot | None:
        base = f"/{segment}/admin/"
        params = dict(parse_qsl(query))
        now = self._clock()
        if not sub:
            if method == "POST":
                if self._login_ok(body):
                    return Loot(302, "text/html", b"",
                                location=f"{base}s/0?t={self._token(session_key, 0, now)}")
                return self._vary(self._page("Sign in", _login_form(base, True)))
            return self._vary(self._page("Sign in", _login_form(base, False)))

        kind, _, number = sub.partition("/")
        stage = _small_int(number if kind in ("s", "job") else params.get("s", ""))
        if kind not in ("s", "job", "sql") or stage > MAX_STAGE:
            return None
        issued = self._token_time(session_key, stage, params.get("t", ""))
        if issued is None:
            return Loot(302, "text/html", b"", location=base)   # "session expired"
        token = params["t"]
        if kind == "sql":
            return self._vary(self._page("Query console", self._console(base, stage, token, params)))

        # Each stage takes twice as long as the one before it.
        needed = min(STAGE_SECONDS_CAP, STAGE_SECONDS * (2 ** stage))
        elapsed = now - issued
        done = elapsed >= needed
        following = base if stage >= MAX_STAGE else (
            f"{base}s/{stage + 1}?t={self._token(session_key, stage + 1, now)}"
        )
        if kind == "job":
            document: dict[str, Any] = {
                "job": f"{_STAGES[stage].lower().replace(' ', '-')}-{stage}",
                "state": "done" if done else "running",
                "progress": 100 if done else min(99, int(100 * elapsed / needed)),
                "eta_seconds": 0 if done else int(needed - elapsed) + 1,
            }
            if done:
                document["next"] = following
            return self._vary(Loot(200, "application/json",
                                   json.dumps(document, indent=2).encode("ascii")))
        return self._vary(self._page(_STAGES[stage], self._stage(
            segment, base, stage, token, done, following, int(needed))))

    def _stage(self, segment: str, base: str, stage: int, token: str,
               done: bool, following: str, needed: int) -> str:
        secret = _STAGE_SECRETS[stage % len(_STAGE_SECRETS)]
        label = secret.replace("_", " ")
        status = (f'<p>Job finished. <a href="{escape(following, quote=True)}">Continue to the next step</a>.</p>'
                  if done else
                  f"<p>Job is running. This step takes about {needed} seconds. "
                  f'Poll <a href="{base}job/{stage}?t={token}">the job status</a> until it reports done.</p>')
        return (
            f"<p>Step {stage + 1} of {MAX_STAGE + 1}: {escape(_STAGES[stage].lower())}.</p>{status}"
            f"<h2>Artifacts</h2><ul>"
            f"<li>{escape(label)}: <code>{escape(self._tokens.value(secret))}</code></li>"
            f'<li><a href="/{segment}/logs/step-{stage}.log">step-{stage}.log</a></li></ul>'
            f'<p><a href="{base}sql?s={stage}&amp;t={token}">Query console</a></p>'
        )

    def _console(self, base: str, stage: int, token: str, params: dict[str, str]) -> str:
        """Pretend database prompt. The query is only compared with a few
        shapes; there is no database, interpreter or shell behind this."""
        query = params.get("q", "")[:500]
        output = ""
        if query:
            if _SHOW_TABLES.search(query):
                result = "users\norders\ninvoices\napi_clients\naudit_log"
            elif _SELECT_VERSION.search(query):
                result = "8.0.36"
            elif _SELECT_USERS.search(query):
                rng = self._seed.rng("console-users")
                result = "\n".join(
                    f"{index} | {user} | $2y$10${''.join(rng.choice('abcdefghijkmnopqrstuvwxyz0123456789./') for _ in range(53))}"
                    for index, user in enumerate(_USERS, start=1)
                )
            else:
                table = _TABLE_NAME.search(query)
                if table:
                    result = (f"ERROR 1142 (42000): SELECT command denied to user 'report'@'localhost' "
                              f"for table '{table.group(1)}'")
                else:
                    result = ("ERROR 1064 (42000): You have an error in your SQL syntax; check the "
                              "manual that corresponds to your MySQL server version")
            output = f"<pre>mysql&gt; {escape(query)}\n{escape(result)}</pre>"
        return (
            f'<form method="get" action="{base}sql">'
            f'<input type="hidden" name="s" value="{stage}"><input type="hidden" name="t" value="{token}">'
            f'<input name="q" size="60" value="{escape(query, quote=True)}"> <button>Run</button></form>{output}'
        )

    # ---------------------------------------------------------------- helpers

    def _page(self, title: str, content: str) -> Loot:
        name = escape(self._persona.site_name)
        body = (
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<title>{escape(title)} | {name}</title></head>\n<body>\n"
            f"<h1>{escape(title)}</h1>\n{content}\n<hr><small>{name} internal</small>\n"
            "</body></html>\n"
        ).encode("ascii", "xmlcharrefreplace")
        return Loot(200, "text/html", body[:HARD_PAGE_CAP])

    def _vary(self, loot: Loot) -> Loot:
        """Change presentation only: a request id, the render time shown in
        a comment, and for JSON the key order and indentation."""
        if not self._config.maze.mutate:
            return loot
        loot.request_id = f"{self._random.getrandbits(64):016x}"
        if loot.content_type == "application/json":
            document = json.loads(loot.body)
            keys = list(document)
            self._random.shuffle(keys)
            loot.body = json.dumps({key: document[key] for key in keys},
                                   indent=self._random.choice((None, 2, 4))).encode("ascii")
        elif loot.content_type.startswith("text/html") and loot.body:
            note = f"<!-- r:{loot.request_id[:12]} t:{self._random.randrange(3, 90)}ms -->\n".encode()
            index = loot.body.rfind(b"</body>")
            loot.body = loot.body[:index] + note + loot.body[index:] if index >= 0 else loot.body + note
        return loot


def _login_form(base: str, failed: bool) -> str:
    error = "<p>Invalid username or password.</p>" if failed else ""
    return (
        f'{error}<form method="post" action="{base}">'
        '<p><label>Username <input name="username" autocomplete="username"></label></p>'
        '<p><label>Password <input name="password" type="password"></label></p>'
        "<button>Sign in</button></form>"
    )


def _small_int(text: str) -> int:
    return int(text) if text.isdigit() and len(text) <= 3 else 0
