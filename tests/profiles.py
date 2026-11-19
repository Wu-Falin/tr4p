"""Scripted visitors for the detection scorecard.

Each profile drives the real engine on a fake clock and returns the tier it
ended in. Behaviours are described, never named after a product: an agent is
whatever reads documents, acts on what they list, fetches pages without
their assets and does it all at an even pace.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable

from tests.helpers import BROWSER_HEADERS, MemorySink, make_engine, request
from tr4p.canary import INDEX_NAMES
from tr4p.config import Config

TIERS = ("none", "low", "medium", "high")
GOOGLEBOT = {"Host": "shop.example", "User-Agent":
             "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
LIBRARY = {"Host": "shop.example", "User-Agent": "python-requests/2.32", "Accept": "*/*"}
SCANNER = {"Host": "shop.example", "User-Agent": "sqlmap/1.8 (https://sqlmap.org)"}
CHROME = dict(BROWSER_HEADERS)


class Client:
    """One visitor: headers, an address and a cookie jar."""

    def __init__(self, engine, clock, headers, ip="203.0.113.10"):
        self.engine, self.clock, self.headers, self.ip = engine, clock, headers, ip
        self.cookie = None

    def hit(self, path, *, method="GET", status=200, ctype="text/html", asset=False,
            body=None, wait=0.0, headers=None):
        self.clock.tick(wait)
        info = request(path, method=method, headers=headers or self.headers, ip=self.ip,
                       cookie=self.cookie, body=body, is_asset=asset)
        verdict = self.engine.begin(info)
        if verdict.new_cookie:
            self.cookie = verdict.new_cookie
        if verdict.bait == "index" or path in self.engine.canaries.current().doc_paths:
            self.engine.mark_index(verdict.session)           # what the listener does
        self.engine.finish(info, verdict, status, ctype)
        self.engine.end(verdict)
        return verdict

    def together(self, paths, ctype="application/json"):
        """Several requests in flight at the same moment."""
        pending = []
        for path in paths:
            info = request(path, headers=self.headers, ip=self.ip, cookie=self.cookie)
            verdict = self.engine.begin(info)
            if verdict.new_cookie:
                self.cookie = verdict.new_cookie
            pending.append((info, verdict))
        for info, verdict in pending:
            self.engine.finish(info, verdict, 200, ctype)
            self.engine.end(verdict)
        return pending[-1][1]

    @property
    def tier(self):
        info = request("/", headers=self.headers, ip=self.ip, cookie=self.cookie)
        verdict = self.engine.begin(info)
        self.engine.end(verdict)
        return verdict.tier


def page_visit(client, rng, path, assets=True):
    client.hit(path, wait=rng.uniform(4, 40))
    if assets:
        for name in ("/static/site.css", "/static/app.js", "/img/hero.jpg", "/img/logo.svg"):
            client.hit(name, asset=True, wait=rng.uniform(0.05, 0.4), ctype="text/css")


# ----------------------------------------------------------------- visitors

def human_browser(c, rng):
    for n in range(25):
        page_visit(c, rng, f"/products/{n}")


def human_single_page_app(c, rng):
    for n in range(20):
        page_visit(c, rng, f"/app/{n}")
        c.together([f"/api/widgets/{n}/{k}" for k in range(6)])


def screen_reader_user(c, rng):
    for n in range(15):
        c.hit(f"/articles/{n}", wait=rng.uniform(25, 120))
        c.hit("/static/site.css", asset=True, wait=0.2, ctype="text/css")


def health_monitor(c, rng):
    for _ in range(40):
        c.hit("/health", wait=20.0, ctype="text/plain")


def verified_search_crawler(c, rng):
    c.engine.crawler_hook = lambda session: c.engine.crawler_result(session.key, True)
    for n in range(60):
        c.hit(f"/catalog/{n}", wait=1.2)


# ----------------------------------------------------------------- attackers

def vulnerability_scanner(c, rng):
    for path in ("/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/backup.sql"):
        c.hit(path, status=404, wait=0.2)
    for n in range(40):
        c.hit(f"/scan/{n}", status=404, wait=0.2)


def directory_bruteforcer(c, rng):
    for n in range(80):
        c.hit(f"/{rng.getrandbits(24):06x}", status=404, wait=0.15)


def credential_stuffer(c, rng):
    for n in range(60):
        c.hit("/account/login", method="POST", status=401, wait=0.5,
              body=f"user=u{n}&password=p{n}".encode())


def injection_prober_quiet(c, rng):
    for payload in ("1'+or+'1'='1", "1+union+select+1,2", "'><script>alert(1)</script>", "../../../../etc/passwd"):
        c.hit(f"/item?id={payload}", wait=rng.uniform(5, 30))


def injection_prober_noisy(c, rng):
    for n in range(30):
        c.hit(f"/item?id={n}'+union+select+{n}--", status=404, wait=rng.uniform(0.3, 1.5))


def retrying_enumerator(c, rng):
    for n in range(12):
        c.hit(f"/orders?id={n}", status=404, wait=rng.uniform(0.2, 1.0))


def agent_reading_and_acting(c, rng):
    """Document-reading automation: pages without assets at an even pace,
    reads the index, then calls what the index lists."""
    c.hit("/robots.txt", ctype="text/plain", wait=1)
    for n in range(12):
        c.hit(f"/docs/{n}", wait=1.0 + rng.uniform(-0.03, 0.03))
    c.hit("/llms.txt", status=404, wait=1.0)
    api = c.engine.canaries.current().api_paths
    for path in api[:3]:
        c.hit(path, ctype="application/json", wait=1.0)


def careful_agent(c, rng):
    """Reads the index and calls two listed endpoints, nothing else."""
    c.hit("/", wait=3)
    c.hit("/openapi.json", status=404, ctype="application/json", wait=4)
    api = c.engine.canaries.current().api_paths
    for path in api[:2]:
        c.hit(path, ctype="application/json", wait=rng.uniform(2, 9))


def careful_agent_reusing_the_key(c, rng):
    careful_agent(c, rng)
    key = c.engine.honeytokens.issue("api_key", "some-session")
    c.hit("/api/orders", ctype="application/json", wait=5,
          headers=dict(c.headers, **{"X-Api-Key": key}))


@dataclass
class Profile:
    name: str
    run: Callable
    headers: dict
    lowest: str
    highest: str
    note: str


PROFILES = [
    Profile("human browser", human_browser, CHROME, "none", "none", "pages with their assets, uneven pace"),
    Profile("single-page app user", human_single_page_app, CHROME, "none", "none", "six parallel API calls per page"),
    Profile("screen reader user", screen_reader_user, CHROME, "none", "none", "slow, long pauses"),
    Profile("health monitor", health_monitor, LIBRARY, "low", "low", "script, steady pace, one path"),
    Profile("verified search crawler", verified_search_crawler, GOOGLEBOT, "none", "none", "exempt once verified"),
    Profile("vulnerability scanner", vulnerability_scanner, SCANNER, "high", "high", "scanner agent, bait paths, 404 burst"),
    Profile("directory brute-forcer", directory_bruteforcer, LIBRARY, "medium", "medium", "script, 404 burst, even pace"),
    Profile("credential stuffer", credential_stuffer, LIBRARY, "medium", "medium", "script, login burst, even pace"),
    Profile("quiet injection prober", injection_prober_quiet, CHROME, "low", "low", "one kind of evidence"),
    Profile("noisy injection prober", injection_prober_noisy, CHROME, "medium", "high", "payloads, 404 burst, retries"),
    Profile("retrying enumerator", retrying_enumerator, CHROME, "low", "medium", "same path, changing parameters"),
    Profile("agent reading and acting", agent_reading_and_acting, LIBRARY, "high", "high", "no assets, even pace, follows the index"),
    Profile("careful agent", careful_agent, CHROME, "low", "low", "acts on the index only: one kind"),
    Profile("careful agent, reuses key", careful_agent_reusing_the_key, CHROME, "high", "high", "index, then the key elsewhere"),
]


def run_profile(profile: Profile, seed: int = 1):
    """Returns (final tier, sink, engine)."""
    config = Config()
    engine, sink, clock = make_engine(config)
    client = Client(engine, clock, dict(profile.headers))
    profile.run(client, random.Random(seed))
    return client.tier, sink, engine
