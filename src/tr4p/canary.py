"""Canaries: places no legitimate visitor ever goes.

Two families live here.

Seed canaries are paths unique to this install. They are advertised only in
places a human never sees (hidden markup, comments, robots.txt) and rotate on
a schedule. Rotated-out canaries stay armed for a while.

Bait paths are the classic targets every scanner asks for (/.env and
friends). They are the same everywhere, which is fine: what is served in
return is derived from the seed.
"""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass
from typing import Callable

from tr4p.seed import Seed

# How a canary was advertised. This decides which signal a hit raises.
KIND_LINK = "link"                # hidden link inside a page
KIND_COMMENT = "comment"          # mentioned in an HTML comment or data block
KIND_ROBOTS = "robots"            # only ever listed in robots.txt
KIND_INSTRUCTION = "instruction"  # hidden text addressed to automated agents

KINDS = (KIND_LINK, KIND_COMMENT, KIND_ROBOTS, KIND_INSTRUCTION)

_DIR_WORDS = (
    "internal", "staging", "backup", "old", "private", "dev", "archive", "tmp",
    "export", "reports", "ops", "staff", "legacy", "beta", "intranet", "vault",
    "admin-backup", "storage", "dumps", "sync", "migrate", "support-tools",
)
_FILE_WORDS = (
    "db-dump", "users-export", "config", "credentials", "notes", "payroll",
    "api-keys", "deploy", "settings", "customers", "audit", "invoices",
    "accounts", "access-log", "passwords", "tokens", "orders", "members",
)
_FILE_ENDINGS = (".sql", ".bak", ".txt", ".json", ".csv", ".env", ".old", ".log", "/")
_AGENT_WORDS = ("agent-check", "verify", "handshake", "session-init", "context", "preflight")

# Scanner targets nothing legitimate ever requests: asking is the signal.
BAIT_ALWAYS = frozenset({
    "/.env", "/.env.local", "/.env.production", "/.env.dev", "/.env.bak",
    "/.env.backup", "/.env.old", "/.env.save", "/api/.env", "/app/.env",
    "/.git/config", "/.git/HEAD", "/.git/index", "/.git/logs/HEAD",
    "/.svn/entries", "/.hg/hgrc", "/.DS_Store", "/.htpasswd", "/.npmrc",
    "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/authorized_keys", "/id_rsa",
    "/.bash_history", "/.docker/config.json", "/.vscode/sftp.json",
    "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old",
    "/wp-config.php.save", "/wp-config.bak", "/config.php.bak", "/config.php~",
    "/config.bak", "/configuration.php.bak", "/settings.py.bak",
    "/web.config.bak", "/database.yml", "/config/database.yml",
    "/backup.sql", "/dump.sql", "/database.sql", "/db.sql", "/db_backup.sql",
    "/data.sql", "/users.sql", "/mysql.sql", "/site.sql",
    "/backup.zip", "/backup.tar.gz", "/backup.tgz", "/site.zip", "/www.zip",
    "/wwwroot.zip", "/htdocs.zip", "/public_html.zip", "/db.zip",
    "/admin-backup", "/admin-backup/", "/shell.php", "/cmd.php", "/c99.php",
    "/wso.php", "/wp-content/debug.log", "/storage/logs/laravel.log",
    "/docker-compose.yml", "/docker-compose.yaml", "/Dockerfile",
    "/actuator/env", "/actuator/heapdump", "/_profiler/phpinfo",
    "/telescope/requests", "/debug/default/view", "/config.json.bak",
    "/credentials.json", "/secrets.json", "/secrets.yml", "/private.key",
    "/server.key", "/.well-known/security.bak",
})

# Admin tools that some real sites do run. Only a signal when the upstream
# says they do not exist.
BAIT_IF_MISSING = frozenset({
    "/phpmyadmin/", "/phpmyadmin", "/pma/", "/pma", "/phpMyAdmin/", "/myadmin/",
    "/adminer.php", "/adminer", "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info", "/wp-login.php", "/xmlrpc.php",
    "/wp-admin/", "/administrator/", "/manager/html", "/jenkins/", "/solr/",
    "/console", "/console/", "/actuator", "/actuator/health", "/swagger-ui.html",
    "/api-docs", "/v2/api-docs", "/graphql", "/cgi-bin/", "/webdav/",
    "/owa/", "/remote/login", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
})


@dataclass(frozen=True)
class CanaryHit:
    kind: str
    rotation: int


@dataclass(frozen=True)
class CanarySet:
    """Everything advertised during one rotation."""

    rotation: int
    segments: dict[str, str]          # kind -> first path segment
    link_paths: tuple[str, ...]
    comment_paths: tuple[str, ...]
    robots_only_path: str
    instruction_path: str

    @property
    def disallow(self) -> tuple[str, ...]:
        """robots.txt entries. Listing every canary directory keeps polite
        crawlers away from all of them."""
        return tuple(f"/{segment}/" for segment in self.segments.values())


class Canaries:
    """Generates the current canary set and recognises hits on armed ones."""

    def __init__(
        self,
        seed: Seed,
        rotation_hours: float = 24.0,
        keep_rotations: int = 7,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._seed = seed
        self._period = max(60.0, rotation_hours * 3600.0)
        self._keep = max(1, keep_rotations)
        self._clock = clock
        self._rotation = -1
        self._current: CanarySet | None = None
        self._armed: dict[str, CanaryHit] = {}

    def rotation(self) -> int:
        return int(self._clock() // self._period)

    def current(self) -> CanarySet:
        self._refresh()
        assert self._current is not None
        return self._current

    def match(self, path: str) -> CanaryHit | None:
        """Return the hit for a request path, or None. One dict lookup."""
        self._refresh()
        if len(path) < 2 or path[0] != "/":
            return None
        end = path.find("/", 1)
        segment = path[1:] if end == -1 else path[1:end]
        return self._armed.get(segment)

    def instruction_token(self, session_key: str) -> str:
        """Token placed in hidden agent instructions for one session."""
        ident = self._seed.hex("instruction-id", session_key, length=12)
        return ident + self._seed.hex("instruction-mac", ident, length=12)

    def check_instruction_token(self, token: str) -> bool:
        if len(token) != 24:
            return False
        ident, mac = token[:12], token[12:]
        expected = self._seed.hex("instruction-mac", ident, length=12)
        return _constant_time_equal(mac, expected)

    def build(self, rotation: int) -> CanarySet:
        """Derive the canary set for a rotation (pure function of the seed)."""
        rng = self._seed.rng("canary", rotation)
        segments: dict[str, str] = {}
        taken: set[str] = set()
        for kind in KINDS:
            while True:
                segment = _segment(rng)
                if segment not in taken:
                    taken.add(segment)
                    segments[kind] = segment
                    break
        links = _distinct_paths(rng, segments[KIND_LINK], 6)
        comments = _distinct_paths(rng, segments[KIND_COMMENT], 3)
        robots_only = f"/{segments[KIND_ROBOTS]}/"
        instruction = f"/{segments[KIND_INSTRUCTION]}/{rng.choice(_AGENT_WORDS)}"
        return CanarySet(
            rotation=rotation,
            segments=segments,
            link_paths=links,
            comment_paths=comments,
            robots_only_path=robots_only,
            instruction_path=instruction,
        )

    def _refresh(self) -> None:
        rotation = self.rotation()
        if rotation == self._rotation:
            return
        armed: dict[str, CanaryHit] = {}
        for past in range(rotation - self._keep + 1, rotation + 1):
            for kind, segment in self.build(past).segments.items():
                armed[segment] = CanaryHit(kind=kind, rotation=past)
        self._armed = armed
        self._current = self.build(rotation)
        self._rotation = rotation


def bait_class(path: str) -> str | None:
    """Classify a path as scanner bait: "always", "if_missing" or None."""
    if path in BAIT_ALWAYS:
        return "always"
    if path in BAIT_IF_MISSING:
        return "if_missing"
    return None


def _segment(rng) -> str:
    """A directory name that looks like leftover internal content.

    A random tag is always included so the name cannot collide with a real
    directory on the protected site.
    """
    word = rng.choice(_DIR_WORDS)
    tag = f"{rng.getrandbits(16):04x}"
    style = rng.randrange(5)
    if style == 0:
        return f"{word}-{tag}"
    if style == 1:
        return f"{word}_{tag}"
    if style == 2:
        return f".{word}-{tag}"
    if style == 3:
        return f"{word}-{rng.choice(_DIR_WORDS)}-{tag[:3]}"
    return f"{tag}-{word}"


def _file_path(rng, segment: str) -> str:
    name = rng.choice(_FILE_WORDS)
    ending = rng.choice(_FILE_ENDINGS)
    if rng.random() < 0.4:
        name = f"{name}-{2019 + rng.randrange(7)}"
    return f"/{segment}/{name}{ending}"


def _distinct_paths(rng, segment: str, count: int) -> tuple[str, ...]:
    paths: list[str] = []
    while len(paths) < count:
        path = _file_path(rng, segment)
        if path not in paths:
            paths.append(path)
    return tuple(paths)


def _constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("ascii", "replace"), right.encode("ascii"))
