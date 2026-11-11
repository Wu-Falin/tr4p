from tests.helpers import Clock, make_seed
from tr4p.canary import (
    BAIT_ALWAYS,
    BAIT_IF_MISSING,
    KIND_INSTRUCTION,
    KIND_LINK,
    KINDS,
    Canaries,
    bait_class,
)
from tr4p.honeytoken import Honeytokens
from tr4p.persona import Persona
from tr4p.seed import Seed


def make(seed=None, keep=3):
    clock = Clock()
    return Canaries(seed or make_seed(), rotation_hours=24, keep_rotations=keep, clock=clock), clock


def test_canaries_are_stable_for_one_install():
    first, _ = make()
    second, _ = make()
    assert first.current() == second.current()


def test_two_installs_share_no_canaries():
    first, _ = make(make_seed(1))
    second, _ = make(make_seed(2))
    assert not set(first.current().segments.values()) & set(second.current().segments.values())
    assert first.current().link_paths != second.current().link_paths


def test_every_kind_has_its_own_directory():
    canaries, _ = make()
    current = canaries.current()
    assert set(current.segments) == set(KINDS)
    assert len(set(current.segments.values())) == len(KINDS)
    assert len(current.disallow) == len(KINDS)


def test_advertised_paths_match_their_kind():
    canaries, _ = make()
    current = canaries.current()
    for path in current.link_paths:
        assert canaries.match(path).kind == KIND_LINK
    assert canaries.match(current.instruction_path).kind == KIND_INSTRUCTION
    assert canaries.match(current.robots_only_path).kind == "robots"
    for path in current.comment_paths:
        assert canaries.match(path).kind == "comment"


def test_ordinary_paths_do_not_match():
    canaries, _ = make()
    for path in ("/", "/index.html", "/backup", "/internal/", "/static/app.js", "", "x"):
        assert canaries.match(path) is None


def test_rotation_changes_canaries_and_keeps_old_ones_armed():
    canaries, clock = make(keep=3)
    old = canaries.current()
    clock.tick(24 * 3600)
    new = canaries.current()
    assert new.rotation == old.rotation + 1
    assert new.segments != old.segments
    hit = canaries.match(old.link_paths[0])
    assert hit is not None and hit.rotation == old.rotation
    clock.tick(3 * 24 * 3600)
    assert canaries.match(old.link_paths[0]) is None


def test_instruction_token_is_signed():
    canaries, _ = make()
    token = canaries.instruction_token("session-a")
    assert canaries.check_instruction_token(token)
    assert token != canaries.instruction_token("session-b")
    assert not canaries.check_instruction_token(token[:-1] + ("0" if token[-1] != "0" else "1"))
    assert not canaries.check_instruction_token("short")
    other, _ = make(make_seed(9))
    assert not other.check_instruction_token(token)


def test_bait_classes():
    assert bait_class("/.env") == "always"
    assert bait_class("/phpmyadmin/") == "if_missing"
    assert bait_class("/") is None
    assert not BAIT_ALWAYS & BAIT_IF_MISSING


def test_honeytokens_differ_per_install_and_are_found():
    first = Honeytokens(make_seed(1))
    second = Honeytokens(make_seed(2))
    assert {t.value for t in first.all()}.isdisjoint({t.value for t in second.all()})
    value = first.value("api_key")
    assert first.find("nothing here") is None
    assert first.find("", f"Bearer {value}").name == "api_key"
    assert second.find(f"Bearer {value}") is None
    assert all(len(t.value) >= 12 for t in first.all())


def test_persona_varies_between_installs():
    seen = {
        (p.banner, p.cookie_name, p.site_name)
        for p in (Persona.from_seed(Seed(bytes([n]) * 32)) for n in range(1, 40))
    }
    assert len(seen) > 20


def test_persona_error_pages_never_name_the_tool():
    for n in range(1, 30):
        persona = Persona.from_seed(Seed(bytes([n]) * 32))
        for status in (400, 403, 404, 500, 502):
            content_type, body = persona.error_page(status, "shop.example:443")
            text = body.decode("ascii").lower()
            assert content_type == "text/html"
            assert str(status) in text
            for word in ("tr4p", "honeypot", "python", "aiohttp", "decoy", "canary"):
                assert word not in text


def test_persona_replays_learned_upstream_pages():
    persona = Persona.from_seed(make_seed())
    persona.learn_banner("gunicorn")
    persona.learn_banner("ignored-second-value")
    persona.learn_not_found(404, "application/json", b'{"error":"nope"}')
    assert persona.server_header == "gunicorn"
    assert persona.error_page(404) == ("application/json", b'{"error":"nope"}')
    assert b"nginx" in persona.error_page(502)[1] or b"Bad Gateway" in persona.error_page(502)[1]
