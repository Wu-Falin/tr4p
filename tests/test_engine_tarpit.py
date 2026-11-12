"""Engine behaviour added with the tarpit: hash-chain cookie, delays and
phases, adaptive bumps, evidence expiry and inherited evidence."""

from tests.helpers import BROWSER_HEADERS, OTHER_IP, SCRIPT_HEADERS, make_engine, make_seed
from tests.test_engine import visit, with_cookie
from tr4p.config import Config
from tr4p.engine import MAX_PHASE


def quiet_config():
    config = Config()
    config.tarpit.jitter = 0.0
    config.tarpit.phase_requests = 1
    return config


def trap_high(engine, **kwargs):
    """Use a planted secret: the one signal that is sufficient by itself."""
    secret = engine.honeytokens.value("api_key")
    headers = dict(kwargs.pop("headers", BROWSER_HEADERS), Authorization=f"Bearer {secret}")
    return visit(engine, "/api", headers=headers, **kwargs)


# ------------------------------------------------------------------ hash chain

def test_chain_cookie_carries_the_phase():
    engine, _, _ = make_engine()
    first = engine.mint_cookie()
    ident, phase = engine.read_cookie(first)
    assert phase == 0
    later = engine.mint_cookie(bytes.fromhex(ident), 5)
    assert engine.read_cookie(later) == (ident, 5)
    assert later != first and len(later) == len(first)


def test_chain_phase_cannot_be_forged_or_moved():
    import base64

    engine, _, _ = make_engine()
    cookie = engine.mint_cookie(phase=3)
    raw = bytearray(base64.urlsafe_b64decode(cookie + "="))
    for forged_phase in (0, 2, 4, 9):
        raw[12] = forged_phase
        forged = base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
        assert engine.read_cookie(forged) is None
    raw[12] = MAX_PHASE + 1
    assert engine.read_cookie(base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")) is None
    other, _, _ = make_engine(seed=make_seed(3))
    assert other.read_cookie(cookie) is None


def test_each_link_depends_on_the_previous_one():
    engine, _, _ = make_engine()
    ident = b"\x01" * 12
    links = [engine._link(ident, phase) for phase in range(6)]
    assert len(set(links)) == 6
    # Cached continuation and a fresh walk from the start agree.
    from tr4p.session import Session
    session = Session(key="x", created=0, last_seen=0)
    assert [engine._link(ident, phase, session) for phase in range(6)] == links
    assert engine._link(ident, 2, session) == links[2]          # going back recomputes


# --------------------------------------------------------------- delays, phases

def test_untrapped_sessions_are_never_delayed():
    engine, _, _ = make_engine(quiet_config())
    cookie = with_cookie(engine)
    assert visit(engine, "/", cookie=cookie).delay == 0
    low = visit(engine, engine.canaries.current().link_paths[0], cookie=cookie)
    assert low.tier == "low" and low.delay == 0


def test_high_tier_delay_doubles_up_to_the_cap():
    engine, _, _ = make_engine(quiet_config())
    cookie = with_cookie(engine)
    delays = [trap_high(engine, cookie=cookie).delay]
    delays += [visit(engine, "/", cookie=cookie).delay for _ in range(7)]
    assert delays == [1, 2, 4, 8, 16, 16, 16, 16]


def test_medium_tier_gets_the_light_tarpit_and_spares_assets():
    engine, _, _ = make_engine(quiet_config())
    canary = engine.canaries.current().link_paths[0]
    delays = [visit(engine, canary, headers=SCRIPT_HEADERS).delay]
    assert visit(engine, "/site.css", headers=SCRIPT_HEADERS, is_asset=True).delay == 0
    for _ in range(4):
        delays.append(visit(engine, "/", headers=SCRIPT_HEADERS).delay)
    assert delays == [1, 2, 2, 2, 2]                              # capped at light_max_delay


def test_phase_requests_and_jitter():
    config = Config()
    config.tarpit.phase_requests = 3
    engine, _, _ = make_engine(config)
    cookie = with_cookie(engine)
    delays = [trap_high(engine, cookie=cookie).delay] + [
        visit(engine, "/", cookie=cookie).delay for _ in range(5)
    ]
    assert all(0.85 <= d <= 1.15 for d in delays[:3])
    assert all(1.7 <= d <= 2.3 for d in delays[3:])
    assert len(set(delays)) > 1                                   # never a fixed number


def test_tarpit_can_be_switched_off():
    config = quiet_config()
    config.tarpit.enabled = False
    engine, _, _ = make_engine(config)
    assert trap_high(engine).delay == 0


def test_cookie_is_reissued_as_the_phase_moves():
    engine, _, _ = make_engine(quiet_config())
    cookie = with_cookie(engine)
    verdict = trap_high(engine, cookie=cookie)
    assert engine.read_cookie(verdict.new_cookie)[1] == 1
    current = verdict.new_cookie
    verdict = visit(engine, "/", cookie=current)
    assert engine.read_cookie(verdict.new_cookie)[1] == 2
    # Replaying the very first cookie gains nothing: the server remembers.
    replay = visit(engine, "/", cookie=cookie)
    assert replay.delay == 4
    assert engine.read_cookie(replay.new_cookie)[1] == 3


def test_restarted_server_resumes_at_the_phase_the_cookie_proves():
    engine, sink, _ = make_engine(quiet_config())
    cookie = with_cookie(engine)
    snapshot_after_trap = None
    verdict = trap_high(engine, cookie=cookie)
    snapshot_after_trap = dict(sink.sessions[verdict.session.key])
    for _ in range(3):
        cookie = verdict.new_cookie or cookie
        verdict = visit(engine, "/", cookie=cookie)
    latest = verdict.new_cookie
    assert engine.read_cookie(latest)[1] == 4

    restarted, _, _ = make_engine(quiet_config())
    snapshot_after_trap["phase"] = 0                              # stale saved state
    restarted.restore([snapshot_after_trap])
    resumed = visit(restarted, "/", cookie=latest)
    assert resumed.delay == 16                                    # phase 4, not phase 0


def test_log_shows_phases_only_while_the_delay_grows():
    engine, sink, _ = make_engine(quiet_config())
    cookie = with_cookie(engine)
    trap_high(engine, cookie=cookie)
    for _ in range(30):
        visit(engine, "/", cookie=cookie)
    assert [e["detail"] for e in sink.kinds("tarpit")] == [f"phase {n}" for n in range(1, 5)]


# ------------------------------------------------------------ adaptive difficulty

def test_bump_only_touches_trapped_sessions():
    engine, sink, _ = make_engine(quiet_config())
    clean = visit(engine, "/")
    assert not engine.bump(clean.session.key, "parallel requests")
    low = visit(engine, engine.canaries.current().link_paths[0], ip=OTHER_IP)
    assert not engine.bump(low.session.key, "parallel requests")
    assert low.session.phase == 0 and not sink.kinds("tarpit")
    assert not engine.bump("unknown", "x")

    cookie = with_cookie(engine, headers=SCRIPT_HEADERS)
    trapped = trap_high(engine, cookie=cookie, headers=SCRIPT_HEADERS)
    before = trapped.session.phase
    assert engine.bump(trapped.session.key, "parallel requests")
    assert trapped.session.phase == before + 1
    assert "parallel requests" in sink.kinds("tarpit")[-1]["detail"]


def test_bump_respects_the_switch_release_and_ceiling():
    config = quiet_config()
    config.tarpit.adaptive = False
    engine, _, _ = make_engine(config)
    trapped = trap_high(engine)
    assert not engine.bump(trapped.session.key, "x")

    engine, _, _ = make_engine(quiet_config())
    trapped = trap_high(engine)
    for _ in range(100):
        engine.bump(trapped.session.key, "x")
    assert trapped.session.phase == MAX_PHASE
    engine.release(trapped.session.key)
    assert trapped.session.phase == 0 and not engine.bump(trapped.session.key, "x")
    assert visit(engine, "/").delay == 0


# ------------------------------------------------------------------- expiry

def test_trap_expires_after_the_lifetime_without_new_signals():
    engine, sink, clock = make_engine(quiet_config())
    cookie = with_cookie(engine)
    trapped = trap_high(engine, cookie=cookie)
    clock.tick(23 * 3600)
    still = visit(engine, "/", cookie=cookie)
    assert still.tier == "high" and still.delay > 0
    clock.tick(25 * 3600)
    after = visit(engine, "/", cookie=still.new_cookie)            # cookie at phase 2
    assert after.tier == "none" and after.delay == 0
    assert trapped.session.signals == {} and trapped.session.phase == 0
    assert engine.read_cookie(after.new_cookie)[1] == 0            # cookie back at the start
    assert sink.kinds("expired") and engine.stats()["expired"] == 1


def test_a_new_signal_restarts_the_lifetime():
    engine, _, clock = make_engine(quiet_config())
    cookie = with_cookie(engine)
    trap_high(engine, cookie=cookie)
    clock.tick(20 * 3600)
    trap_high(engine, cookie=cookie)
    clock.tick(20 * 3600)
    assert visit(engine, "/", cookie=cookie).tier == "high"


def test_low_tier_evidence_expires_too():
    engine, _, clock = make_engine()
    cookie = with_cookie(engine)
    canary = engine.canaries.current().link_paths[0]
    visit(engine, canary, cookie=cookie)
    clock.tick(25 * 3600)
    assert visit(engine, "/", cookie=cookie).tier == "none"


# ----------------------------------------------------------- inherited evidence

def test_new_cookie_inherits_at_reduced_weight_and_never_reaches_high():
    engine, _, _ = make_engine(quiet_config())
    group = trap_high(engine, headers=SCRIPT_HEADERS)             # cookie-less: tracked as a group
    assert group.tier == "high"
    fresh = visit(engine, "/", headers=SCRIPT_HEADERS, cookie=group.new_cookie)
    session = fresh.session
    assert session is not group.session
    assert session.signals == {"generic_client": 1}
    assert "honeytoken" in session.inherited
    assert fresh.tier == "medium"                                 # capped: inherited alone is never high
    assert session.score == 80.0                                  # 100 * 0.7 inherited + own client 10
    assert 0 < fresh.delay <= 2


def test_own_signals_on_top_of_inherited_evidence_restore_high():
    engine, _, _ = make_engine(quiet_config())
    canary = engine.canaries.current().link_paths[0]
    group = visit(engine, canary, headers=SCRIPT_HEADERS)
    for n in range(45):
        group = visit(engine, f"/p/{n}", headers=SCRIPT_HEADERS)
    assert group.tier == "high"
    fresh = visit(engine, "/", headers=SCRIPT_HEADERS, cookie=group.new_cookie)
    assert fresh.tier == "medium"
    again = visit(engine, canary, headers=SCRIPT_HEADERS, cookie=fresh.new_cookie or group.new_cookie)
    assert again.tier == "high"


def test_inherited_evidence_is_forgotten_after_its_short_lifetime():
    engine, sink, clock = make_engine(quiet_config())
    headers = dict(BROWSER_HEADERS)
    group = trap_high(engine, headers=headers)
    fresh = visit(engine, "/", headers=headers, cookie=group.new_cookie)
    assert fresh.tier == "medium" and fresh.session.signals == {}
    clock.tick(31 * 60)
    later = visit(engine, "/", headers=headers, cookie=group.new_cookie)
    assert later.tier == "none" and later.delay == 0
    assert later.session.inherited == {}
    assert sink.kinds("expired")


def test_weak_trap_does_not_survive_a_change_of_identity():
    # Evidence worth 45 (medium) is worth less when merely inherited: a
    # look-alike behind the same address is left alone.
    engine, _, _ = make_engine(quiet_config())
    group = visit(engine, "/.env", status=404, headers=SCRIPT_HEADERS)
    assert group.tier == "medium" and group.session.score == 45.0
    fresh = visit(engine, "/", headers=SCRIPT_HEADERS, cookie=group.new_cookie)
    assert fresh.session.inherited == {"probe_path": 1, "generic_client": 1}
    assert fresh.session.score == 34.5                            # 35 * 0.7 + own client 10
    assert fresh.tier == "low" and fresh.delay == 0


def test_inherited_weight_is_configurable():
    config = quiet_config()
    config.detection.inherited_weight = 0.0
    engine, _, _ = make_engine(config)
    group = trap_high(engine)
    fresh = visit(engine, "/", cookie=group.new_cookie)
    assert fresh.tier == "low" and fresh.delay == 0


def test_snapshot_round_trip_keeps_tarpit_state():
    from tr4p.session import Session

    engine, sink, _ = make_engine(quiet_config())
    group = trap_high(engine)
    visit(engine, "/", cookie=group.new_cookie)
    for snapshot in sink.sessions.values():
        restored = Session.restore(snapshot)
        assert restored.snapshot() == snapshot
