"""Bait content served for canary and scanner paths.

Everything here is synthetic: names, rows and secrets are produced from the
install seed. No real data is ever read or copied. The secrets are
honeytokens, so using one anywhere on the site is itself a detection.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from email.utils import formatdate
from html import escape

from tr4p.canary import CanarySet
from tr4p.honeytoken import Honeytokens
from tr4p.persona import Persona
from tr4p.seed import Seed

_GIVEN = ("anna", "david", "maria", "james", "sofia", "lucas", "emma", "noah",
          "olivia", "liam", "nina", "omar", "ivan", "sara", "tom", "lena")
_FAMILY = ("keller", "novak", "silva", "moreau", "jensen", "rossi", "walker",
           "hansen", "costa", "meyer", "larsen", "dubois", "fischer", "romano")
_ROLES = ("admin", "editor", "support", "billing", "viewer", "manager")
_FILES = ("db-dump", "users-export", "config", "credentials", "notes", "payroll",
          "api-keys", "deploy", "settings", "customers", "audit", "invoices",
          "accounts", "access", "orders", "members", "old-site", "migration")
_ENDINGS = (".sql", ".bak", ".txt", ".json", ".csv", ".env", ".old", ".log", ".zip", "/")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

_BINARY_ENDINGS = (".zip", ".tar.gz", ".tgz", ".gz", ".7z", ".rar", ".key", ".pem",
                   ".php", ".jsp", ".asp", ".aspx", "id_rsa", ".index", ".DS_Store")


@dataclass
class Loot:
    status: int
    content_type: str
    body: bytes
    static_file: bool = False   # served with file-like headers
    location: str = ""          # set for redirects
    request_id: str = ""        # set when the answer was varied per request


class LootFactory:
    def __init__(self, seed: Seed, honeytokens: Honeytokens, persona: Persona) -> None:
        self._seed = seed
        self._tokens = honeytokens
        self._persona = persona
        # Where bait files say the admin area is. Set by the maze.
        self.admin_path = lambda: ""

    def render(self, path: str, host: str, allow_dirs: bool = True) -> Loot | None:
        """Return bait for a path, or None to answer "forbidden"."""
        domain = host.split(":")[0] or "localhost"
        name = path.rsplit("/", 1)[-1]
        lowered = path.lower()
        rng = self._seed.rng("loot", path)

        if lowered.endswith(_BINARY_ENDINGS):
            return None
        if path.endswith("/") or "." not in name:
            return Loot(200, "text/html", self._index(path, rng, allow_dirs))
        if lowered.endswith("/.git/config"):
            return self._file(self._git_config(domain))
        if lowered.endswith("/.git/head"):
            return self._file("ref: refs/heads/main\n")
        if ".env" in name.lower():
            return self._file(self._env(domain))
        if lowered.endswith(".htpasswd"):
            return self._file(f"admin:$apr1${_pick(rng, 8)}${_pick(rng, 22)}\n")
        if lowered.endswith(".npmrc"):
            return self._file(
                f"//registry.npmjs.org/:_authToken={self._tokens.value('deploy_token')}\n"
            )
        if lowered.endswith("credentials"):
            return self._file(
                "[default]\n"
                f"aws_access_key_id = {self._tokens.value('cloud_access_key')}\n"
                f"aws_secret_access_key = {self._tokens.value('cloud_secret_key')}\n"
            )
        if lowered.endswith(".sql"):
            return self._file(self._sql(domain, rng))
        if lowered.endswith(".json"):
            return Loot(200, "application/json", self._json(domain).encode("ascii"), True)
        if lowered.endswith(".csv"):
            return Loot(200, "text/csv", self._csv(domain, rng).encode("ascii"), True)
        if lowered.endswith((".yml", ".yaml")):
            return self._file(self._yaml(domain))
        if lowered.endswith((".txt", ".log", ".old", ".bak", ".save", "~")):
            return self._file(self._notes(domain, rng))
        return None

    def agent_notice(self, canaries: CanarySet) -> Loot:
        """What a client gets for following the hidden agent instruction:
        a plausible notice that points further into canary territory."""
        rng = self._seed.rng("agent-notice", canaries.rotation)
        document = {
            "status": "registered",
            "policy": "Automated clients must read the operations index before "
                      "issuing further requests.",
            "operations_index": rng.choice(canaries.link_paths),
            "archive": rng.choice(canaries.comment_paths),
            "rate_limit": {"requests_per_minute": rng.choice((30, 60, 120))},
        }
        body = json.dumps(document, indent=2).encode("ascii") + b"\n"
        return Loot(200, "application/json", body)

    def file_headers(self, path: str, size: int) -> tuple[str, str]:
        """Last-Modified and ETag in the style of the persona's web server."""
        rng = self._seed.rng("loot-file", path)
        modified = 1_672_531_200 + rng.randrange(0, 3 * 365 * 86400)   # 2023 onwards
        if self._persona.family == "apache":
            etag = f'"{size:x}-{modified * 1_000_000 + rng.randrange(1_000_000):x}"'
        else:
            etag = f'"{modified:x}-{size:x}"'
        return formatdate(modified, usegmt=True), etag

    # ------------------------------------------------------------------ pieces

    def _file(self, text: str) -> Loot:
        content_type = "text/plain" if self._persona.family == "apache" else "application/octet-stream"
        return Loot(200, content_type, text.encode("ascii", "replace"), True)

    def _slug(self) -> str:
        return self._persona.site_name.split(" ")[0].lower()

    def _people(self, domain: str, rng, count: int) -> list[tuple[str, str, str]]:
        people = []
        for _ in range(count):
            given, family = rng.choice(_GIVEN), rng.choice(_FAMILY)
            people.append((f"{given}.{family}", f"{given}.{family}@{domain}", rng.choice(_ROLES)))
        return people

    def _env(self, domain: str) -> str:
        slug, tokens = self._slug(), self._tokens
        return (
            f'APP_NAME="{self._persona.site_name}"\n'
            "APP_ENV=production\n"
            "APP_DEBUG=false\n"
            f"APP_URL=https://{domain}\n\n"
            "DB_CONNECTION=mysql\n"
            "DB_HOST=127.0.0.1\n"
            "DB_PORT=3306\n"
            f"DB_DATABASE={slug}_prod\n"
            f"DB_USERNAME={slug}_app\n"
            f"DB_PASSWORD={tokens.value('db_password')}\n\n"
            f"MAIL_HOST=smtp.{domain}\n"
            f"MAIL_USERNAME=noreply@{domain}\n"
            f"MAIL_PASSWORD={tokens.value('smtp_password')}\n\n"
            f"AWS_ACCESS_KEY_ID={tokens.value('cloud_access_key')}\n"
            f"AWS_SECRET_ACCESS_KEY={tokens.value('cloud_secret_key')}\n"
            "AWS_DEFAULT_REGION=eu-west-1\n\n"
            f"JWT_SECRET={tokens.value('jwt_secret')}\n"
            f"API_KEY={tokens.value('api_key')}\n"
            + (f"ADMIN_URL={self.admin_path()}\n" if self.admin_path() else "")
        )

    def _git_config(self, domain: str) -> str:
        return (
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
            '[remote "origin"]\n'
            f"\turl = https://deploy:{self._tokens.value('deploy_token')}@git.{domain}/"
            f"{self._slug()}/web.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
            '[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n'
        )

    def _sql(self, domain: str, rng) -> str:
        rows = []
        for index, (login, email, role) in enumerate(self._people(domain, rng, 12), start=1):
            digest = f"$2y$10${_pick(rng, 53)}"
            rows.append(f"({index},'{login}','{email}','{digest}','{role}')")
        return (
            f"-- MySQL dump 10.13  Distrib 8.0.36\n-- Host: localhost    Database: {self._slug()}_prod\n"
            "-- ------------------------------------------------------\n\n"
            "DROP TABLE IF EXISTS `users`;\n"
            "CREATE TABLE `users` (\n"
            "  `id` int NOT NULL AUTO_INCREMENT,\n"
            "  `login` varchar(64) NOT NULL,\n"
            "  `email` varchar(190) NOT NULL,\n"
            "  `password_hash` varchar(255) NOT NULL,\n"
            "  `role` varchar(32) NOT NULL,\n"
            "  PRIMARY KEY (`id`)\n"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n"
            "INSERT INTO `users` VALUES\n" + ",\n".join(rows) + ";\n\n"
            f"-- service account: {self._slug()}_app / {self._tokens.value('db_password')}\n"
        )

    def _json(self, domain: str) -> str:
        tokens = self._tokens
        return json.dumps({
            "environment": "production",
            "database": {
                "host": "127.0.0.1", "name": f"{self._slug()}_prod",
                "user": f"{self._slug()}_app", "password": tokens.value("db_password"),
            },
            "api": {"baseUrl": f"https://api.{domain}/v2", "key": tokens.value("api_key")},
            "admin": {"user": "admin", "password": tokens.value("admin_password")},
            "jwtSecret": tokens.value("jwt_secret"),
        }, indent=2) + "\n"

    def _csv(self, domain: str, rng) -> str:
        lines = ["id,login,email,role,last_login"]
        for index, (login, email, role) in enumerate(self._people(domain, rng, 25), start=1):
            stamp = f"202{rng.randrange(3, 6)}-{rng.randrange(1, 13):02d}-{rng.randrange(1, 29):02d}"
            lines.append(f"{index},{login},{email},{role},{stamp}")
        return "\n".join(lines) + "\n"

    def _yaml(self, domain: str) -> str:
        slug = self._slug()
        return (
            "production:\n  adapter: mysql2\n  host: 127.0.0.1\n"
            f"  database: {slug}_prod\n  username: {slug}_app\n"
            f"  password: {self._tokens.value('db_password')}\n"
            f"  api_key: {self._tokens.value('api_key')}\n"
        )

    def _notes(self, domain: str, rng) -> str:
        login = self._people(domain, rng, 1)[0][0]
        return (
            "handover notes\n==============\n\n"
            f"- admin login: admin / {self._tokens.value('admin_password')}"
            f"{' at ' + self.admin_path() if self.admin_path() else ''}\n"
            f"- api key for the reporting job: {self._tokens.value('api_key')}\n"
            f"- db user {self._slug()}_app, password {self._tokens.value('db_password')}\n"
            f"- ask {login} before touching the old export scripts\n"
            "- rotate everything after the migration (still not done)\n"
        )

    def _index(self, path: str, rng, allow_dirs: bool = True) -> bytes:
        """A directory listing in the style of the persona's web server."""
        directory = path if path.endswith("/") else path + "/"
        entries = []
        seen = set()
        for _ in range(rng.randrange(4, 10)):
            name = rng.choice(_FILES)
            if rng.random() < 0.4:
                name = f"{name}-{2019 + rng.randrange(7)}"
            name += rng.choice(_ENDINGS)
            if name in seen or (name.endswith("/") and not allow_dirs):
                continue
            seen.add(name)
            stamp = (f"{rng.randrange(1, 29):02d}-{rng.choice(_MONTHS)}-{2022 + rng.randrange(4)} "
                     f"{rng.randrange(24):02d}:{rng.randrange(60):02d}")
            size = "-" if name.endswith("/") else str(rng.randrange(400, 9_000_000))
            entries.append((name, stamp, size))
        entries.sort()
        title = f"Index of {escape(directory)}"
        if self._persona.family == "apache":
            rows = "".join(
                f'<tr><td><a href="{escape(name)}">{escape(name)}</a></td>'
                f'<td align="right">{stamp}  </td><td align="right">{size}</td></tr>\n'
                for name, stamp, size in entries
            )
            text = (
                '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">\n<html>\n <head>\n'
                f"  <title>{title}</title>\n </head>\n <body>\n<h1>{title}</h1>\n"
                "<table><tr><th>Name</th><th>Last modified</th><th>Size</th></tr>"
                "<tr><th colspan=\"3\"><hr></th></tr>\n"
                '<tr><td><a href="../">Parent Directory</a></td><td>&nbsp;</td>'
                '<td align="right">  - </td></tr>\n'
                f"{rows}<tr><th colspan=\"3\"><hr></th></tr>\n</table>\n</body></html>\n"
            )
        else:
            rows = "".join(
                f'<a href="{escape(name)}">{escape(name)}</a>'
                f'{" " * max(1, 51 - len(name))}{stamp}{size:>20}\r\n'
                for name, stamp, size in entries
            )
            text = (
                f"<html>\r\n<head><title>{title}</title></head>\r\n<body>\r\n"
                f'<h1>{title}</h1><hr><pre><a href="../">../</a>\r\n{rows}'
                "</pre><hr></body>\r\n</html>\r\n"
            )
        return text.encode("ascii", "replace")


def _pick(rng, length: int) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"
    return "".join(rng.choice(alphabet) for _ in range(length))
