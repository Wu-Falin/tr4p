"""Behavioural evidence kinds, discovery bait with follow-through, per-session
secrets with linking, and the bait cookie."""

import json
import random

import pytest

from tests.helpers import BROWSER_HEADERS, OTHER_IP, SCRIPT_HEADERS, Clock, make_engine, make_seed, request
from tests.http_helpers import BROWSER, ListenerCase
from tests.profiles import Client
from tr4p.canary import INDEX_NAMES, bait_class
from tr4p.config import Config, ConfigError
from tr4p.honeytoken import Honeytokens
from tr4p.scoring import STRONG_GROUPS, confidence, tier_for
from tr4p.config import DEFAULT_WEIGHTS


def client(config=None, headers=None, ip="203.0.113.10"):
    engine, sink, clock = make_engine(config or Config())
    return Client(engine, clock, dict(headers or BROWSER_HEADERS), ip), engine, sink


def kinds(sink):
    return [e["signal"] for e in sink.kinds("signal")]


# ------------------------------------------------------------ steady pace

def test_even_pace_is_noted_once_uneven_pace_never():
    c, engine, sink = client()
    for n in range(25):
        c.hit(f"/p/{n}", wait=2.0)
    assert kinds(sink).count("cadence") == 1
    c, engine, sink = client()
    rng = random.Random(4)
    for n in range(60):
        c.hit(f"/p/{n}", wait=rng.uniform(1, 9))
    assert "cadence" not in kinds(sink)


def test_pauses_assets_and_short_runs_do_not_count_as_pace():
    c, _, sink = client()
    for n in range(40):
        c.hit(f"/p/{n}", wait=60.0)                               # gaps of a minute are pauses
    for n in range(40):
        c.hit(f"/img/{n}.png", asset=True, wait=0.5)              # assets are not pages
    for n in range(10):
        c.hit(f"/q/{n}", wait=2.0)                                # too few gaps yet
    assert "cadence" not in kinds(sink)


def test_cadence_settings_are_validated():
    for patch in ({"cadence_min_gaps": 3}, {"cadence_max_spread": 0}, {"concurrency_min": 1}, {"retry_min": 1}):
        with pytest.raises(ConfigError):
            Config.from_dict({"detection": patch})


# ------------------------------------------------------------ concurrency, retry

def test_many_page_requests_in_flight_are_noted_but_ordinary_parallelism_is_not():
    c, _, sink = client()
    c.together([f"/api/{n}" for n in range(6)])
    assert "concurrency" not in kinds(sink)
    c, engine, sink = client()
    c.together([f"/api/{n}" for n in range(12)])
    assert kinds(sink) == ["concurrency"]
    assert engine.sessions.get(next(iter(engine.sessions.flagged())).key).inflight == 0   # all ended


def test_retries_with_changed_parameters_after_an_error():
    c, _, sink = client()
    for n in range(7):
        c.hit(f"/orders?id={n}", status=404, wait=0.5)
    assert kinds(sink) == ["retry_pattern"]
    c, _, sink = client()
    for n in range(8):
        c.hit("/orders?id=1", status=404, wait=0.5)               # same request again: a plain retry
    for n in range(8):
        c.hit(f"/o{n}?id={n}", status=404, wait=0.5)              # different paths each time
    c.hit("/login", method="POST", status=401, wait=0.5)
    assert "retry_pattern" not in kinds(sink)


# ------------------------------------------------------- the strong-kind rule

def test_weak_kinds_alone_never_make_the_high_tier():
    signals = {"generic_client": 1, "cadence": 1, "retry_pattern": 1, "rate": 1}
    score = confidence(signals, DEFAULT_WEIGHTS)
    assert score >= 70
    assert tier_for(signals, score, 40, 70, 3) == "medium"
    with_payload = dict(signals, attack_payload=1)
    assert tier_for(with_payload, confidence(with_payload, DEFAULT_WEIGHTS), 40, 70, 3) == "high"
    assert {"payload", "follow_through", "honeytoken", "tamper", "enumeration"} <= STRONG_GROUPS
    assert not STRONG_GROUPS & {"cadence", "concurrency", "retry", "client", "volume", "fetch_pattern"}


# ------------------------------------------------------ per-session secrets

def test_secrets_are_issued_per_session_and_traced_back():
    tokens = Honeytokens(make_seed())
    first, second = tokens.issue("api_key", "session-a"), tokens.issue("api_key", "session-b")
    assert first != second and first[:-8] == second[:-8] == tokens.value("api_key")[:-8]
    assert len(first) == len(tokens.value("api_key"))
    found = tokens.find(f"Bearer {first}")
    assert (found.name, found.origin, found.install) == ("api_key", "session-a", False)
    assert tokens.find(second).origin == "session-b"
    install = tokens.find(tokens.value("api_key"))
    assert install.install and install.origin is None


def test_altered_or_foreign_secrets_are_still_recognised_but_not_traced():
    tokens = Honeytokens(make_seed())
    issued = tokens.issue("db_password", "session-a")
    assert tokens.find(issued[:-3] + "xyz").origin is None            # tag no longer matches
    long_one = tokens.issue("api_key", "session-a")
    assert tokens.find(long_one[:-8]).name == "api_key"               # only the fixed part kept
    assert tokens.find("prefix " + issued + " suffix").origin == "session-a"
    assert Honeytokens(make_seed(9)).find(issued) is None             # another install
    assert Honeytokens(make_seed()).find(issued).origin is None       # forgotten after a restart


def test_each_secret_keeps_its_own_alphabet():
    tokens = Honeytokens(make_seed())
    for token in tokens.all():
        issued = tokens.issue(token.name, "session-a")
        assert len(issued) == len(token.value) >= 12
    assert set(tokens.issue("jwt_secret", "s")) <= set("0123456789abcdef")
    assert set(tokens.issue("cloud_access_key", "s")) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def test_a_secret_reused_in_another_session_links_them_into_one_campaign():
    first, engine, sink = client()
    first.hit(engine.canaries.current().link_paths[0], wait=1)        # some evidence on the first
    origin = next(iter(engine.sessions.flagged()))
    key = engine.honeytokens.issue("api_key", origin.key)
    second = Client(engine, first.clock, dict(SCRIPT_HEADERS), OTHER_IP)
    second.hit("/api/orders", headers=dict(SCRIPT_HEADERS, **{"X-Api-Key": key}), wait=1)
    later = next(s for s in engine.sessions.flagged() if s.key != origin.key)
    assert later.campaign == origin.campaign == origin.key[:10]
    assert later.tier == "high" and "canary_path" in later.inherited   # the earlier session's evidence
    assert sink.kinds("link") and origin.key[:8] in sink.kinds("link")[0]["detail"]
    assert later.snapshot()["campaign"] == origin.campaign


# --------------------------------------------------------------- bait cookie

def test_privileged_values_in_the_bait_cookie_are_tampering():
    engine, sink, _ = make_engine()
    for value, expected in (("admin", True), ("TRUE", True), ("1", True), (engine.honey_cookie_value, False), ("blue", False)):
        info = request("/", cookie=None)
        info.honey_cookie = value
        verdict = engine.begin(info)
        engine.end(verdict)
        assert ("tamper" in verdict.session.signals) == expected, value
        verdict.session.signals.clear()


# ------------------------------------------------------- discovery bait, served

def test_index_names_are_a_distinct_bait_class():
    assert all(bait_class(name) == "index" for name in INDEX_NAMES)
    assert bait_class("/.env") == "always" and bait_class("/phpmyadmin/") == "if_missing"


class Discovery(ListenerCase):
    def paths(self):
        return self.engine.canaries.current().api_paths

    async def test_conventional_names_are_served_only_when_the_site_lacks_them(self):
        own, body = await self.get("/llms.txt")
        self.assertEqual(body, b"the site's own llms file")                   # the site has one
        doc, body = await self.get("/openapi.json")
        document = json.loads(body)
        self.assertEqual(list(document["paths"]), list(self.paths()))
        self.assertEqual(doc.headers["Server"], "gunicorn")
        self.assert_anonymous(doc, body)
        key = document["components"]["securitySchemes"]["apiKey"]["description"].split(": ")[1]
        self.assertEqual(self.engine.honeytokens.find(key).name, "api_key")
        self.assertEqual(self.signals(), [])                                  # reading is not a signal
        self.assertTrue(any(s.index_read for s in self.engine.sessions._clean.values()))

    async def test_graphql_is_canned_and_never_run(self):
        response, body = await self.get("/graphql")
        self.assertIn(b"Must provide query string", body)
        async with self.client.post(
            self.base + "/graphql", data=b'{"query":"{ __schema { types { name } } }"}',
            headers=dict(BROWSER, **{"Content-Type": "application/json"})) as response:
            schema = json.loads(await response.read())
        self.assertEqual(schema["data"]["__schema"]["queryType"], {"name": "Query"})
        async with self.client.post(
            self.base + "/graphql", data=b'{"query":"{ users { password } } mutation { drop }"}',
            headers=dict(BROWSER, **{"Content-Type": "application/json"})) as response:
            self.assertIn("Unauthorized", (await response.read()).decode())

    async def test_other_documents_list_the_same_endpoints(self):
        for name in ("/.well-known/tool-manifest.json", "/swagger.json"):
            _, body = await self.get(name)
            self.assertIn(self.paths()[0], body.decode())

    async def test_acting_on_what_a_document_lists_is_the_signal(self):
        response, _ = await self.get("/openapi.json")
        cookie = response.headers["Set-Cookie"].split(";")[0]
        listed, body = await self.get(self.paths()[0], headers=dict(BROWSER, Cookie=cookie))
        self.assertEqual(listed.status, 200)
        data = json.loads(body)
        self.assertTrue(data["links"]["next"] in self.paths())               # leads to the next one
        self.assertEqual(self.signals(), ["follow_through"])
        unlisted, body = await self.get(self.paths()[0].rsplit("/", 1)[0] + "/not-listed",
                                        headers=dict(BROWSER, Cookie=cookie))
        self.assertEqual((unlisted.status, json.loads(body)), (404, {"error": "not_found"}))
        self.assertEqual(self.signals(), ["follow_through", "enumeration"])
        self.assert_anonymous(unlisted, body)

    async def test_the_same_endpoint_without_reading_a_document_is_only_a_canary_hit(self):
        await self.get(self.paths()[1])
        self.assertEqual(self.signals(), ["canary_path"])

    async def test_documents_inside_the_hidden_directory_also_count_as_reading(self):
        doc = self.engine.canaries.current().doc_paths[0]
        response, body = await self.get(doc)
        self.assertEqual(response.status, 200)
        self.assertEqual(self.signals(), ["canary_path"])
        cookie = response.headers["Set-Cookie"].split(";")[0]
        await self.get(self.paths()[2], headers=dict(BROWSER, Cookie=cookie))
        self.assertEqual(self.signals(), ["canary_path", "follow_through"])
        self.assertTrue(set(self.engine.canaries.current().disallow) >= {"/" + self.paths()[0].split("/")[1] + "/"})


class Secrets(ListenerCase):
    async def test_bait_secrets_differ_per_session_and_link_sessions(self):
        first, body_one = await self.get("/.env", headers=BROWSER)
        second, body_two = await self.get("/.env", headers=dict(BROWSER, **{"User-Agent": "Mozilla/5.0 Firefox/130"}))
        key = lambda body: next(l.split("=", 1)[1] for l in body.decode().splitlines() if l.startswith("API_KEY="))
        self.assertNotEqual(key(body_one), key(body_two))
        await self.get("/api/data", headers=dict(BROWSER, **{"User-Agent": "other/1", "X-Api-Key": key(body_one)}))
        self.assertTrue(self.sink.kinds("link"))
        campaigns = {s.campaign for s in self.engine.sessions.flagged() if s.campaign}
        self.assertEqual(len(campaigns), 1)

    async def test_bait_cookie_is_set_on_trap_pages_only_and_never_reaches_the_site(self):
        name, value = self.engine.honey_cookie_name, self.engine.honey_cookie_value
        bait, _ = await self.get("/.env")
        cookies = bait.headers.getall("Set-Cookie")
        self.assertTrue(cookies[0].startswith(self.persona.cookie_name + "="))       # session cookie first
        self.assertIn(f"{name}={value}; Path=/; HttpOnly; SameSite=Lax", cookies)
        home, _ = await self.get("/")
        self.assertFalse(any(c.startswith(name) for c in home.headers.getall("Set-Cookie", [])))
        doc, _ = await self.get("/openapi.json")
        self.assertFalse(any(c.startswith(name) for c in doc.headers.getall("Set-Cookie", [])))
        async with self.client.get(self.base + "/echo", headers=dict(
                BROWSER, Accept="application/json", Cookie=f"app=1; {name}={value}")) as response:
            self.assertEqual(json.loads(await response.read())["headers"]["cookie"], "app=1")
        before = self.signals().count("tamper")
        await self.get("/", headers=dict(BROWSER, Cookie=f"{name}=admin"))
        self.assertEqual(self.signals().count("tamper"), before + 1)
