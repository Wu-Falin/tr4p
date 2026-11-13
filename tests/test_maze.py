"""Rabbit hole, token-burn pages, fake kill chain, maze and teleport."""

import json
import re
import time

from tests.helpers import Clock, make_seed
from tests.http_helpers import BROWSER, ListenerCase
from tr4p.config import Config
from tr4p.engine import Engine
from tr4p.loot import LootFactory
from tr4p.maze import HARD_PAGE_CAP, MAX_HOPS, MAX_STAGE, SMALL_PAGE, Maze
from tr4p.persona import Persona
from tests.helpers import MemorySink

COMMENT = re.compile(rb"<!-- r:[0-9a-f]+ t:\d+ms -->\n")


def build(mutate=True, **maze):
    seed = make_seed()
    config = Config()
    config.maze.mutate = mutate
    for name, value in maze.items():
        setattr(config.maze, name, value)
    clock = Clock()
    engine = Engine(config, seed, MemorySink(), clock)
    persona = Persona.from_seed(seed)
    made = Maze(seed, config, engine.canaries, engine.honeytokens, persona,
                LootFactory(seed, engine.honeytokens, persona), clock)
    return made, engine, clock


def ask(made, path, method="GET", query="", body=None, key="session-a", trapped=True):
    return made.respond(method, path, query, body, "shop.example", key, trapped)


def segment(engine, kind):
    return engine.canaries.current().segments[kind]


# ----------------------------------------------------------------- token burn

def test_burn_page_is_deterministic_sized_and_capped():
    made, engine, _ = build()
    path = f"/{segment(engine, 'link')}/logs/app.log"
    first, again = ask(made, path), ask(made, path)
    assert first.body == again.body
    assert len(first.body) == 32768
    assert ask(made, path + "x.log").body != first.body
    assert len(ask(made, path, trapped=False).body) == SMALL_PAGE      # visitors get a short one
    assert len(made._burn_log(path, "/x/", 10 ** 9)) == HARD_PAGE_CAP
    assert first.body.decode("ascii").count("\n") > 200


def test_burn_page_is_poisoned_and_uses_no_real_addresses():
    made, engine, _ = build(burn_bytes=131072)
    text = ask(made, f"/{segment(engine, 'comment')}/x/audit.log").body.decode()
    assert engine.honeytokens.value("api_key") in text
    assert made.admin_path() in text
    addresses = set(re.findall(r"ip=(\S+)", text))
    assert addresses and all(address.startswith("203.0.113.") for address in addresses)


def test_burn_generation_is_cheap():
    made, engine, _ = build(burn_bytes=524288)
    started = time.perf_counter()
    ask(made, f"/{segment(engine, 'link')}/big.log")
    assert time.perf_counter() - started < 0.5


# ---------------------------------------------------------------- rabbit hole

def test_directory_tree_stops_at_the_configured_depth():
    made, engine, _ = build(rabbit_depth=2)
    root = f"/{segment(engine, 'link')}/"
    found_dir = False
    for n in range(30):
        shallow = ask(made, f"{root}d{n}/").body.decode()
        found_dir = found_dir or bool(re.search(r'href="[^".][^"]*/"', shallow))
        deep = ask(made, f"{root}d{n}/e/").body.decode()
        assert not re.search(r'href="[^".][^"]*/"', deep)           # no way further down
        assert "Index of" in deep
    assert found_dir                                                 # above the limit there is


# ----------------------------------------------------------------------- maze

def test_maze_nodes_are_stateless_and_endless():
    made, engine, _ = build(mutate=False)
    base = f"/{segment(engine, 'robots')}/m/"
    page = ask(made, base + "0000abc1")
    assert page.status == 200 and page.body == ask(made, base + "0000abc1").body
    assert len(page.body) <= 32768 + 4096
    links = re.findall(rb'href="(/[^"]+/m/[0-9a-f]{8})"', page.body)
    assert len(links) >= 5
    following = ask(made, links[0].decode())
    assert following is not None and following.status in (200, 302)
    assert ask(made, base + "not-a-node") is None
    assert ask(made, base + "../../etc/passwd") is None


def test_redirect_chains_are_bounded():
    made, engine, _ = build()
    path, query, hops = f"/{segment(engine, 'robots')}/m/00000004", "", 0
    while True:
        answer = ask(made, path, query=query)
        if answer.status != 302:
            break
        hops += 1
        path, _, query = answer.location.partition("?")
        assert hops <= MAX_HOPS
    assert answer.status == 200 and hops >= 1


def test_mutation_changes_presentation_not_facts():
    made, engine, _ = build()
    node = f"/{segment(engine, 'robots')}/m/0000abc1"
    first, second = ask(made, node), ask(made, node)
    assert first.body != second.body and first.request_id != second.request_id
    assert COMMENT.sub(b"", first.body) == COMMENT.sub(b"", second.body)
    notice = engine.canaries.current().instruction_path
    documents = [ask(made, notice) for _ in range(8)]
    assert len({d.body for d in documents}) > 1
    assert len({json.dumps(json.loads(d.body), sort_keys=True) for d in documents}) == 1


def test_files_stay_byte_identical():
    made, engine, _ = build()
    path = f"/{segment(engine, 'link')}/settings.env"
    assert ask(made, path).body == ask(made, path).body and not ask(made, path).request_id


# ----------------------------------------------------------------- kill chain

def login(made, engine, body, key="session-a"):
    return ask(made, made.admin_path(), method="POST", body=body, key=key)


def good_login(made, engine, key="session-a"):
    password = engine.honeytokens.value("admin_password")
    answer = login(made, engine, f"username=admin&password={password}".encode(), key)
    assert answer.status == 302
    return answer.location


def test_bait_points_at_the_fake_admin_area():
    made, engine, _ = build()
    env = ask(made, f"/{segment(engine, 'link')}/prod.env").body.decode()
    assert f"ADMIN_URL={made.admin_path()}" in env
    assert b"<form" in ask(made, made.admin_path()).body


def test_only_planted_credentials_or_an_injection_string_get_in():
    made, engine, _ = build()
    assert login(made, engine, b"username=admin&password=wrong-guess").status == 200
    assert login(made, engine, b"").status == 200
    assert login(made, engine, None).status == 200
    assert "/admin/s/0?t=" in good_login(made, engine)
    assert login(made, engine, b"username=a'+or+'1'%3D'1&password=x").status == 302


def test_stage_tokens_are_bound_to_session_stage_and_time():
    made, engine, clock = build()
    location = good_login(made, engine)
    path, _, query = location.partition("?")
    assert ask(made, path, query=query).status == 200
    assert ask(made, path, query=query, key="someone-else").status == 302      # not theirs
    assert ask(made, path.replace("/s/0", "/s/1"), query=query).status == 302   # wrong stage
    assert ask(made, path, query=query[:-1] + ("0" if query[-1] != "0" else "1")).status == 302
    assert ask(made, path, query="t=zz-zz").status == 302
    assert ask(made, path.replace("/s/0", f"/s/{MAX_STAGE + 1}"), query=query) is None
    clock.tick(2 * 86400)
    assert ask(made, path, query=query).status == 302                           # expired


def test_each_stage_takes_twice_as_long():
    made, engine, clock = build(mutate=False)
    location = good_login(made, engine)
    waits = []
    for stage in range(4):
        path, _, query = location.partition("?")
        job = path.replace(f"/s/{stage}", f"/job/{stage}")
        state = json.loads(ask(made, job, query=query).body)
        assert state["state"] == "running" and "next" not in state
        waits.append(state["eta_seconds"])
        clock.tick(state["eta_seconds"] - 2)
        assert json.loads(ask(made, job, query=query).body)["state"] == "running"
        clock.tick(3)
        state = json.loads(ask(made, job, query=query).body)
        assert state["state"] == "done" and state["progress"] == 100
        assert b"Continue to the next step" in ask(made, path, query=query).body
        location = state["next"]
    assert waits == [16, 31, 61, 121]


def test_stage_pages_hand_out_poisoned_secrets():
    made, engine, _ = build()
    path, _, query = good_login(made, engine).partition("?")
    page = ask(made, path, query=query).body.decode()
    assert engine.honeytokens.value("api_key") in page
    assert "/logs/step-0.log" in page and "/admin/sql?" in page


def test_console_is_an_emulation_that_echoes_escaped_text():
    made, engine, _ = build(mutate=False)
    path, _, query = good_login(made, engine).partition("?")
    console = path.replace("/s/0", "/sql")

    def run(text):
        from urllib.parse import quote
        return ask(made, console, query=f"s=0&{query}&q={quote(text)}").body.decode()

    assert "audit_log" in run("show tables")
    assert "anna.keller" in run("SELECT login, hash FROM users LIMIT 5")
    assert "8.0.36" in run("select @@version")
    assert "ERROR 1142" in run("select * from orders")
    hostile = "x'; DROP TABLE users; --<script>alert(1)</script> $(id) `id` ../../etc/passwd"
    out = run(hostile)
    assert "ERROR 1064" in out
    assert "<script>" not in out and "&lt;script&gt;" in out
    assert run(hostile) == out                                       # nothing changed anywhere
    assert "anna.keller" in run("select * from users")               # the "table" is still there
    assert ask(made, console, query="s=0&t=bad&q=show+tables").status == 302


# ------------------------------------------------------------------- teleport

def test_teleport_target_is_internal_unless_configured():
    made, engine, _ = build()
    assert re.fullmatch(rf"/{re.escape(segment(engine, 'robots'))}/m/[0-9a-f]{{8}}", made.teleport_target())
    made, _, _ = build(external_targets=["https://maze.example/a"])
    assert made.teleport_target() == "https://maze.example/a"
    assert Config().maze.external_targets == []


class Teleport(ListenerCase):
    def configure(self, config):
        config.tarpit.enabled = True
        config.tarpit.base_delay = config.tarpit.max_delay = config.tarpit.light_max_delay = 0.1
        config.maze.redirect_chance = 1.0
        config.maze.redirect_min_phase = 0

    async def test_only_high_tier_requests_are_sent_into_the_maze(self):
        clean, _ = await self.get("/")
        self.assertEqual(clean.status, 200)
        curl = {"User-Agent": "curl/8.5.0", "Accept": "*/*"}
        await self.get(self.engine.canaries.current().link_paths[0], headers=curl)   # medium
        medium, _ = await self.get("/", headers=curl)
        self.assertEqual(medium.status, 200)

        secret = self.engine.honeytokens.value("api_key")
        high = dict(BROWSER, Authorization=f"Bearer {secret}")
        response, body = await self.get("/", headers=high)
        self.assertEqual(response.status, 302)
        target = response.headers["Location"]
        self.assertTrue(target.startswith(f"/{self.engine.canaries.current().segments['robots']}/m/"))
        self.assert_anonymous(response, body)
        asset, _ = await self.get("/static/app.css", headers=high)                   # assets pass
        self.assertEqual(asset.status, 200)
        page, body = await self.get(target, headers=high)
        self.assertIn(page.status, (200, 302))
        self.assertEqual(self.engine.stats()["teleported"], 1)

    async def test_fake_admin_area_end_to_end(self):
        admin = self.app._maze.admin_path()
        password = self.engine.honeytokens.value("admin_password")
        async with self.client.post(
            self.base + admin, data=f"username=admin&password={password}".encode(),
            headers=dict(BROWSER, **{"Content-Type": "application/x-www-form-urlencoded"}),
            allow_redirects=False,
        ) as response:
            self.assertEqual(response.status, 302)
            self.assertIn("/admin/s/0?t=", response.headers["Location"])
        self.assertIn("honeytoken", self.signals())                 # using the bait is detected
        self.assertEqual(self.engine.stats()["tiers"]["high"], 1)
