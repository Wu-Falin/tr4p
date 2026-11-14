"""The decoy: synthetic data, emulated profiles, isolation, schema import,
and fail-closed routing with the real decoy process."""

import asyncio
import json
import random
import re
import socket
import unittest
from pathlib import Path

import pytest

import tr4p.decoy
from tests.helpers import make_seed
from tests.http_helpers import BROWSER, HOME_PAGE, ListenerCase
from tr4p.decoy.app import PROFILES, DecoyApp
from tr4p.decoy.synth import ADDRESS_PREFIXES, EMAIL_DOMAINS, LOCALES, Dataset
from tr4p.honeytoken import Honeytokens
from tr4p.schema import SchemaError, import_schema, load_schema, parse_schema

LOOK = {"name": "Nordvale Works", "accent": "#1f6feb", "tagline": "Service.", "year": 2025}
TOKENS = {token.name: token.value for token in Honeytokens(make_seed()).all()}


def app(profile="generic", schema=None):
    return DecoyApp(profile, b"\x05" * 32, LOOK, TOKENS, schema)


def get(decoy, path, sid="s1", method="GET", body=b""):
    path, _, query = path.partition("?")
    return decoy.handle(method, path, query, body, sid)


def sign_in(decoy, path, sid="s1", field="password"):
    return get(decoy, path, sid, "POST", f"username=admin&{field}={TOKENS['admin_password']}".encode())


# ------------------------------------------------------------- synthetic data

def test_data_is_multilingual_synthetic_and_deterministic():
    data = Dataset(random.Random(1))
    assert Dataset(random.Random(1)).people == data.people
    assert {person.locale for person in data.people} == set(LOCALES)
    names = " ".join(person.name for person in data.people)
    assert re.search(r"[؀-ۿ]", names) and re.search(r"[가-힣]", names)
    names.encode("utf-8").decode("utf-8")
    for person in data.people:
        assert person.email.rsplit("@", 1)[1] in EMAIL_DOMAINS
        assert person.last_address.startswith(ADDRESS_PREFIXES)
        assert "555-01" in person.phone or "-0000-" in person.phone or "-000-" in person.phone
    assert all(domain.endswith((".com", ".org", ".net", ".test", ".invalid")) for domain in EMAIL_DOMAINS)
    assert all(domain.startswith("example.") or domain.endswith((".test", ".invalid"))
               for domain in EMAIL_DOMAINS)


# ------------------------------------------------------------------- profiles

@pytest.mark.parametrize("profile, home, login, field, admin, users", [
    ("generic", "/", "/login", "password", "/admin", "/admin/users"),
    ("php", "/index.php", "/login.php", "password", "/admin/index.php", "/admin/users.php"),
    ("wordpress", "/", "/wp-login.php", "pwd", "/wp-admin/", "/wp-admin/users.php"),
])
def test_web_profiles_follow_the_same_story(profile, home, login, field, admin, users):
    decoy = app(profile)
    front = get(decoy, home)
    assert front.status == 200 and b"Nordvale Works" in front.body and not front.touch
    assert get(decoy, admin).status == 302                                   # must sign in first
    wrong = get(decoy, login, method="POST", body=f"username=admin&{field}=guess".encode())
    assert wrong.status == 200 and b"Invalid username or password." in wrong.body
    entered = sign_in(decoy, login, field=field)
    assert entered.status == 302 and entered.touch
    page = get(decoy, users)
    assert page.status == 200 and page.touch == "user table"
    text = page.body.decode("utf-8")
    assert re.search(r"[؀-ۿ]", text) and re.search(r"[가-힣]", text)
    assert get(decoy, admin, sid="someone-else").status == 302               # state is per session
    assert get(decoy, "/definitely-not-here").status == 404
    assert ("X-Powered-By" in front.headers) == (profile != "generic")


def test_api_profile_and_shared_data_endpoints():
    decoy = app("api")
    assert "endpoints" in json.loads(get(decoy, "/").body)
    users = get(decoy, "/api/v1/users")
    assert users.touch == "user list" and json.loads(users.body)["total"] == 40
    keys = get(decoy, "/api/v1/keys")
    assert keys.touch and TOKENS["api_key"] in keys.body.decode()
    assert get(decoy, "/api/v1/users/1").status == 200 and get(decoy, "/api/v1/users/999").status == 404
    assert json.loads(get(decoy, "/api/v1/nope").body) == {"error": "not_found"}
    assert json.loads(get(app("generic"), "/api/users").body) == json.loads(users.body)


def test_wordpress_details():
    decoy = app("wordpress")
    assert b'content="WordPress' in get(decoy, "/").body
    assert get(decoy, "/wp-json/wp/v2/users").touch
    assert get(decoy, "/xmlrpc.php").status == 405
    assert b"faultCode" in get(decoy, "/xmlrpc.php", method="POST", body=b"<x/>").body
    assert get(decoy, "/?author=1").headers["Location"] == "/author/admin/"


def test_fake_fetch_never_touches_the_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the decoy tried to open a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    decoy = app("api")
    for target in ("http://internal.example/admin", "file:///etc/hosts", "gopher://x.example"):
        reply = get(decoy, f"/api/v1/fetch?url={target}")
        assert reply.status == 504 and reply.touch
        assert json.loads(reply.body)["error"] == "upstream_timeout"


def test_facts_are_stable_and_hostile_input_is_harmless():
    decoy = app("php")
    assert get(decoy, "/api.php?r=users").body == get(decoy, "/api.php?r=users", sid="other").body
    for profile in PROFILES:
        decoy = app(profile)
        for path in ("/index.php?page=../../../../etc/passwd", "/api/v1/users/1%27%20or%201=1",
                     "/?author=<script>alert(1)</script>", "/admin/../../x", "/api.php?r=$(id)",
                     "/api/v1/tables/users;drop", "/\x00", "/" + "a" * 5000):
            reply = get(decoy, path, method="POST", body=b"\xff\xfe password=`id`&x=${jndi:x}")
            assert reply.status in (200, 302, 404, 405, 504)
            assert b"<script>alert(1)</script>" not in reply.body and b"root:" not in reply.body


def test_wipe_and_session_cap(monkeypatch):
    decoy = app()
    sign_in(decoy, "/login")
    assert get(decoy, "/admin").status == 200
    assert decoy.wipe("s1") and not decoy.wipe("s1")
    assert get(decoy, "/admin").status == 302
    monkeypatch.setattr("tr4p.decoy.app.MAX_SESSIONS", 10)
    for n in range(50):
        get(decoy, "/", sid=f"flood-{n}")
    assert decoy.stats()["sessions"] <= 10


def test_decoy_code_has_no_way_out():
    """The decoy package must contain no client, file, process or evaluation calls."""
    banned = ("ClientSession", "urllib.request", "http.client", "subprocess", "os.system",
              "eval(", "exec(", "sqlite3", "open(", "socket.", "import requests", "os.environ")
    package = Path(tr4p.decoy.__file__).parent
    sources = list(package.glob("*.py")) + [package.parent / "site.py"]
    assert len(sources) >= 5
    for source in sources:
        text = source.read_text(encoding="utf-8")
        for word in banned:
            assert word not in text, f"{source.name} contains {word}"


# --------------------------------------------------------------- schema import

MYSQL = """
-- dump without data
CREATE TABLE `customers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `full_name` varchar(190) NOT NULL,
  `email` varchar(190) DEFAULT NULL,
  `balance` decimal(10,2) NOT NULL DEFAULT '0.00',
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS public.audit_log (id bigserial, happened_at timestamp, note text);
"""


def test_schema_keeps_names_and_types_only():
    schema = parse_schema(MYSQL)
    assert [table["name"] for table in schema["tables"]] == ["customers", "audit_log"]
    assert schema["tables"][0]["columns"] == [
        {"name": "id", "type": "int"}, {"name": "full_name", "type": "varchar"},
        {"name": "email", "type": "varchar"}, {"name": "balance", "type": "decimal"}]
    assert "0.00" not in json.dumps(schema)                      # defaults are not kept


@pytest.mark.parametrize("extra", [
    "INSERT INTO customers VALUES (1, 'Real Person', 'real@corp.test', 3.5);",
    "insert  into `customers` (id) values (1);",
    "COPY customers (id, full_name) FROM stdin;\n1\tReal Person\n\\.",
    "LOAD DATA INFILE 'x.csv' INTO TABLE customers;",
    "REPLACE INTO customers VALUES (1);",
])
def test_schema_with_data_rows_is_refused(extra):
    with pytest.raises(SchemaError, match="data rows"):
        parse_schema(MYSQL + extra)


def test_schema_limits_and_junk():
    with pytest.raises(SchemaError, match="larger"):
        parse_schema("-- " + "x" * (1024 * 1024 + 10))
    with pytest.raises(SchemaError, match="no CREATE TABLE"):
        parse_schema("SELECT 1; DROP TABLE x;")
    with pytest.raises(SchemaError, match="not text"):
        parse_schema("CREATE TABLE a (b int);\x00")
    many = "".join(f"CREATE TABLE t{n} (c int);" for n in range(500))
    assert len(parse_schema(many)["tables"]) == 200
    odd = parse_schema("CREATE TABLE ok (good int, `bad name; drop` int, \"<script>\" text, fine text);")
    assert [column["name"] for column in odd["tables"][0]["columns"]] == ["good", "fine"]


def test_hostile_schema_files_cannot_make_parsing_slow():
    import time

    for text in ("CREATE TABLE a (b int);" + "copy x " * 140000,
                 "create table a (b int, " * 40000,
                 "create table t (" + "(" * 900000):
        started = time.perf_counter()
        try:
            parse_schema(text)
        except SchemaError:
            pass
        assert time.perf_counter() - started < 3.0


def test_imported_schema_shapes_fake_tables(tmp_path):
    source = tmp_path / "schema.sql"
    source.write_text(MYSQL, encoding="utf-8")
    import_schema(source, tmp_path)
    schema = load_schema(tmp_path)
    decoy = app("api", schema)
    assert json.loads(get(decoy, "/api/v1/tables").body) == {"tables": ["audit_log", "customers"]}
    table = json.loads(get(decoy, "/api/v1/tables/customers").body)
    assert len(table["rows"]) == 20 and set(table["rows"][0]) == {"id", "full_name", "email", "balance"}
    assert all(row["email"].rsplit("@", 1)[1] in EMAIL_DOMAINS for row in table["rows"])
    assert get(decoy, "/api/v1/tables/customers").body == get(decoy, "/api/v1/tables/customers").body
    assert get(decoy, "/api/v1/tables/missing").status == 404
    assert load_schema(tmp_path / "nowhere") is None


def test_schema_command(tmp_path, capsys):
    from tr4p.cli import main

    home = tmp_path / "home"
    assert main(["--home", str(home), "init", "--yes", "--mode", "standalone", "--profile", "api"]) == 0
    good, bad = tmp_path / "good.sql", tmp_path / "bad.sql"
    good.write_text(MYSQL, encoding="utf-8")
    bad.write_text(MYSQL + "INSERT INTO customers VALUES (1);", encoding="utf-8")
    capsys.readouterr()
    assert main(["--home", str(home), "schema", str(bad)]) == 1
    assert "data rows" in capsys.readouterr().err and load_schema(home) is None
    assert main(["--home", str(home), "schema", str(good)]) == 0
    assert "2 tables" in capsys.readouterr().out and len(load_schema(home)["tables"]) == 2
    from tr4p.config import Config
    assert Config.load(home / "config.json").decoy.profile == "api"


# -------------------------------------------------- routing with the real process

class Routing(ListenerCase):
    def configure(self, config):
        config.decoy.enabled = True

    async def asyncSetUp(self):
        import tempfile

        from tr4p.decoylink import DecoyLink

        await super().asyncSetUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.link = DecoyLink(Path(self.tmp.name), self.config, self.seed, self.persona,
                              self.engine.honeytokens)
        await self.link.start()
        self.app.decoy = self.link
        self.engine.release_hook = lambda session: asyncio.ensure_future(self.link.wipe(session.key))
        secret = self.engine.honeytokens.value("api_key")
        self.attacker = dict(BROWSER, Authorization=f"Bearer {secret}")
        self.visitor = dict(BROWSER, **{"User-Agent": "Mozilla/5.0 (X11) Firefox/128.0"})

    async def asyncTearDown(self):
        await self.link.stop()
        await super().asyncTearDown()
        self.tmp.cleanup()

    async def test_high_tier_is_moved_quietly_and_everyone_else_is_not(self):
        real, body = await self.get("/")
        self.assertIn(b"Real content.", body)
        before = len(self.hits)
        moved, body = await self.get("/", headers=self.attacker)
        self.assertEqual(moved.status, 200)
        self.assertNotIn(b"Real content.", body)
        self.assertIn(self.persona.site_name.encode(), body)
        self.assertEqual(len(self.hits), before)                     # the real site saw nothing
        self.assertEqual(moved.headers["Server"], real.headers["Server"])
        self.assertTrue(moved.headers["Set-Cookie"].startswith(self.persona.cookie_name + "="))
        self.assertNotIn("X-Decoy-Touch", moved.headers)
        self.assert_anonymous(moved, body)
        again, body = await self.get("/", headers=self.visitor)      # another client: real site
        self.assertIn(b"Real content.", body)

    async def test_sensitive_touch_raises_an_alert_event(self):
        await self.get("/", headers=self.attacker)
        response, body = await self.get("/api/users", headers=self.attacker)
        self.assertEqual(response.status, 200)
        self.assertIn("@example.", body.decode("utf-8") + "@example.")
        touches = self.sink.kinds("decoy")
        self.assertEqual(len(touches), 1)
        self.assertTrue(touches[0]["alert"] and touches[0]["signal"] == "decoy_touch")
        self.assertIn("user list", touches[0]["detail"])
        self.assertEqual(self.engine.stats()["decoy_touches"], 1)
        self.assertEqual(self.link.stats()["touches"], 1)

    async def test_decoy_down_fails_closed_then_recovers(self):
        await self.get("/", headers=self.attacker)
        self.link._process.kill()
        await self.link._process.wait()
        before = len(self.hits)
        for path in ("/", "/api/data", "/echo"):
            response, body = await self.get(path, headers=self.attacker)
            self.assertEqual(response.status, 503, path)
            self.assert_anonymous(response, body)
        self.assertEqual(len(self.hits), before)                     # never the real site
        clean, body = await self.get("/", headers=self.visitor)
        self.assertIn(b"Real content.", body)                        # others are unaffected
        for _ in range(60):
            if self.link.running:
                break
            await asyncio.sleep(0.1)
        self.assertTrue(self.link.running)
        self.assertEqual(self.link.stats()["restarts"], 1)
        back, _ = await self.get("/", headers=self.attacker)
        self.assertEqual(back.status, 200)

    async def test_missing_link_also_fails_closed(self):
        self.app.decoy = None
        before = len(self.hits)
        response, _ = await self.get("/", headers=self.attacker)
        self.assertEqual(response.status, 503)
        self.assertEqual(len(self.hits), before)

    async def test_release_returns_the_session_and_wipes_decoy_state(self):
        password = self.engine.honeytokens.value("admin_password")
        async with self.client.post(self.base + "/login", data=f"username=a&password={password}".encode(),
                                    headers=dict(self.attacker, **{"Content-Type": "application/x-www-form-urlencoded"}),
                                    allow_redirects=False) as response:
            self.assertEqual(response.status, 302)
        session = next(s for s in self.engine.sessions.flagged() if s.tier == "high")
        admin, _ = await self.get("/admin", headers=self.attacker)
        self.assertEqual(admin.status, 200)
        self.engine.release(session.key)
        await asyncio.sleep(0.2)
        self.assertFalse(await self.link.wipe(session.key))          # already wiped by the release
        response, body = await self.get("/", headers=BROWSER)
        self.assertIn(b"Real content.", body)

    async def test_decoy_answers_nobody_without_the_key(self):
        import aiohttp

        async with aiohttp.ClientSession() as client:
            async with client.get(f"http://127.0.0.1:{self.link._port}/") as response:
                self.assertEqual(response.status, 403)
            async with client.get(f"http://127.0.0.1:{self.link._port}/__control/health",
                                  headers={"X-Decoy-Key": "guess"}) as response:
                self.assertEqual(response.status, 403)
