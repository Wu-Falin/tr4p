"""Browser test of the dashboard: headless Chromium against the real service.

Dev and CI only: needs the `e2e` extra (playwright) and a Chromium build. The
whole module is skipped when playwright is not installed, so the normal test
run and the runtime never depend on it.

Set TR4P_E2E_SHOTS to a directory to keep the screenshots (CI uploads them).
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import threading
import time
from pathlib import Path

import pytest

playwright_api = pytest.importorskip("playwright.sync_api")
expect = playwright_api.expect

from tests.helpers import make_seed, request, MemorySink  # noqa: E402
from tr4p.bus import EventBus  # noqa: E402
from tr4p.config import Config  # noqa: E402
from tr4p.dashboard import auth  # noqa: E402
from tr4p.dashboard.app import Dashboard  # noqa: E402
from tr4p.engine import Engine  # noqa: E402
from tr4p.store import Store  # noqa: E402

PASSWORD = "correct horse battery"
HOSTILE = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>"\'&amp;'
SHOTS = os.environ.get("TR4P_E2E_SHOTS")
DESKTOP = {"width": 1280, "height": 900}
MOBILE = {"width": 390, "height": 844}


# ------------------------------------------------------------------ the server

class Server:
    """A real dashboard on a loopback port, running on its own thread."""

    def __init__(self, password: bool = True) -> None:
        self.password = password
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.tmp = tempfile.TemporaryDirectory()
        self.config = Config()
        self.config.dashboard.port = 0
        self.contexts: list = []

    def start(self) -> "Server":
        self.thread.start()
        self.call(self._build, wait=True)
        return self

    def call(self, fn, wait: bool = True):
        async def run():
            result = fn()
            return await result if asyncio.iscoroutine(result) else result
        return asyncio.run_coroutine_threadsafe(run(), self.loop).result(30)

    async def _build(self):
        self.store = Store(Path(self.tmp.name) / "events.db")
        self.store.open()
        if self.password:
            self.store.set_setting("dashboard_password", auth.hash_password(PASSWORD))
        self.bus = EventBus()
        store, bus = self.store, self.bus

        class Sink(MemorySink):
            def event(self, event):
                store.add_event(event)
                bus.publish(event)

        self.engine = Engine(self.config, make_seed(), Sink())

        async def apply_settings(changes, note):
            self.config.apply(changes)

        self.dashboard = Dashboard(
            self.config, self.engine, self.store, self.bus, "instance-1",
            status=lambda: {"running": True, "mode": "proxy", "uptime": 3725.0,
                            "stats": self.engine.stats(), "level": 3,
                            "alerts": {"configured": False}, "decoy": {"enabled": False}},
            apply_settings=apply_settings,
        )
        await self.dashboard.start()
        self.config.dashboard.port = self.dashboard.port          # the real port, so settings validate
        self.base = f"http://127.0.0.1:{self.dashboard.port}"
        if not self.password:
            self.dashboard.setup_code = auth.new_setup_code()

    @property
    def setup_code(self) -> str:
        return self.dashboard.setup_code

    def hit(self, path: str, agent: str = HOSTILE, ip: str = "203.0.113.77") -> None:
        def go():
            info = request(path, headers={"Host": "x.example", "User-Agent": agent}, ip=ip)
            self.engine.finish(info, self.engine.begin(info), 404, "")
            self.store.flush()
        self.call(go)

    def seed(self) -> None:
        """One live session with hostile text, two linked by a campaign."""
        self.hit(self.engine.canaries.current().link_paths[0])
        self.hit("/.env?" + HOSTILE)
        now = time.time()

        def restore():
            for key, ip, score in (("aaaa1111", "198.51.100.9", 61.0), ("bbbb2222", HOSTILE, 83.5)):
                self.engine.restore([{
                    "key": key, "ip": ip, "user_agent": HOSTILE, "tier": "high" if score > 80 else "medium",
                    "score": score, "phase": 2, "campaign": HOSTILE, "theme": "database",
                    "created": now - 300, "last_seen": now - 20, "requests": 12, "hits": 3,
                    "held_seconds": 30.5, "served_bytes": 8192,
                    "signals": {"canary_path": 2, "attack_payload": 1, "honeytoken": 1}}])
                self.store.add_event({"ts": now - 60, "kind": "signal", "session": key, "ip": ip,
                                      "method": "GET", "path": "/x" + HOSTILE, "signal": "attack_payload",
                                      "detail": HOSTILE, "score": score, "tier": "medium",
                                      "user_agent": HOSTILE, "alert": 1})
            self.store.flush()
        self.call(restore)

    def stop(self) -> None:
        for context in self.contexts:          # open live streams would hold the shutdown
            try:
                context.close()
            except Exception:
                pass

        async def down():
            await self.dashboard.stop()
            self.store.close()
        self.call(down)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.tmp.cleanup()


@pytest.fixture
def server():
    srv = Server().start()
    yield srv
    srv.stop()


@pytest.fixture
def fresh_server():
    srv = Server(password=False).start()
    yield srv
    srv.stop()


@pytest.fixture(scope="module")
def browser():
    with playwright_api.sync_playwright() as pw:
        options = {"executable_path": os.environ["TR4P_CHROMIUM"]} if os.environ.get("TR4P_CHROMIUM") else {}
        instance = pw.chromium.launch(**options)
        yield instance
        instance.close()


# ----------------------------------------------------------------- page helpers

class Watch:
    """Collects everything that should never happen on the page."""

    def __init__(self, page, base: str) -> None:
        self.problems: list[str] = []
        page.on("pageerror", lambda e: self.problems.append(f"page error: {e}"))
        page.on("console", lambda m: m.type == "error" and self.problems.append(f"console: {m.text}"))
        page.on("request", lambda r: not r.url.startswith(base) and not r.url.startswith("data:")
                and self.problems.append(f"external request: {r.url}"))

    def expect_clean(self, allow: tuple[str, ...] = ()) -> None:
        left = [p for p in self.problems if not any(a in p for a in allow)]
        assert not left, left


def new_page(browser, server, viewport=DESKTOP, scheme="light", sign_in=True):
    context = browser.new_context(viewport=viewport, color_scheme=scheme, accept_downloads=True)
    server.contexts.append(context)
    if sign_in:
        reply = context.request.post(server.base + "/api/v1/login", data={"password": PASSWORD},
                                     headers={"X-Requested-With": "dashboard"})
        assert reply.ok
    page = context.new_page()
    page.set_default_timeout(8000)
    return context, page, Watch(page, server.base)


def open_console(page, server):
    page.goto(server.base + "/")
    page.locator("#s-requests").wait_for()
    expect(page.locator("#s-requests")).not_to_have_text("-")


def shot(page, name: str) -> None:
    if SHOTS:
        Path(SHOTS).mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(Path(SHOTS) / f"{name}.png"), full_page=True)


def assert_inert(page) -> None:
    assert page.evaluate("window.__pwned") is None
    assert page.locator("img[src='x']").count() == 0
    assert page.locator("main script").count() == 0


CONTRAST = """() => {
  const rgba = c => { const n = (c.match(/[\\d.]+/g) || []).map(Number);
    const k = c.startsWith('color(') ? 255 : 1;
    return {r: n[0]*k, g: n[1]*k, b: n[2]*k, a: n.length > 3 ? n[3] : 1}; };
  const lin = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
  const lum = c => 0.2126*lin(c.r) + 0.7152*lin(c.g) + 0.0722*lin(c.b);
  const back = el => { for (let e = el; e; e = e.parentElement) {
    const c = rgba(getComputedStyle(e).backgroundColor); if (c.a > 0.99) return c; }
    return {r: 255, g: 255, b: 255, a: 1}; };
  const bad = [];
  for (const el of document.querySelectorAll('body *')) {
    if (el.closest('.visually-hidden, [hidden], svg') || !el.offsetParent && getComputedStyle(el).position !== 'fixed') continue;
    const own = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if (!own) continue;
    const style = getComputedStyle(el);
    const fg = rgba(style.color), bg = back(el);
    const a = lum(fg), b = lum(bg);
    const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    const large = parseFloat(style.fontSize) >= 24 || (parseFloat(style.fontSize) >= 18.66 && Number(style.fontWeight) >= 700);
    if (ratio < (large ? 3 : 4.5)) bad.push(el.tagName + ' ' + el.textContent.trim().slice(0, 30) + ' ' + ratio.toFixed(2));
  }
  return bad; }"""


# ------------------------------------------------------------------------ tests

def test_first_run_setup_then_login_and_logout(browser, fresh_server):
    srv = fresh_server
    context, page, watch = new_page(browser, srv, sign_in=False)
    page.goto(srv.base + "/")
    assert page.url.endswith("/setup")                      # no password yet: forced setup
    page.fill("#code", "WRONG-WRONG-WRON")
    page.fill("#password", PASSWORD)
    page.fill("#confirm", PASSWORD)
    page.click("button[type=submit]")
    expect(page.locator("#error")).to_contain_text("Setup code is not correct")
    page.fill("#code", srv.setup_code)
    page.fill("#password", "short")
    page.fill("#confirm", "short")
    page.click("button[type=submit]")
    expect(page.locator("#error")).not_to_have_text("Setup code is not correct")
    expect(page.locator("#error")).to_be_visible()
    page.fill("#password", PASSWORD)
    page.fill("#confirm", PASSWORD + "x")
    page.click("button[type=submit]")
    expect(page.locator("#error")).to_contain_text("match", ignore_case=True)
    page.fill("#confirm", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(srv.base + "/")
    page.locator("#h-summary").wait_for()
    page.click("#logout")
    page.wait_for_url("**/login")
    page.fill("#password", "not the password")
    page.click("button[type=submit]")
    expect(page.locator("#error")).to_contain_text("Wrong password")
    page.fill("#password", PASSWORD)
    page.click("button[type=submit]")
    page.wait_for_url(srv.base + "/")
    page.locator("#h-summary").wait_for()
    watch.expect_clean(allow=("401", "403", "400"))          # failed attempts are logged by the browser
    context.close()


@pytest.mark.parametrize("name,viewport", [("desktop", DESKTOP), ("mobile", MOBILE)])
def test_console_end_to_end(browser, server, name, viewport):
    server.seed()
    context, page, watch = new_page(browser, server, viewport)
    open_console(page, server)

    # sessions, campaign column, hostile text rendered as text
    rows = page.locator("#sessions tr")
    rows.first.wait_for()
    assert rows.count() == 3
    assert page.locator("#sessions-table th", has_text="Campaign").count() == 1
    assert "<img src=x" in page.locator("#sessions").inner_text()          # literal, not markup
    assert_inert(page)
    assert page.locator("#sessions td.num", has_text="<img src").count() == 2   # campaign, first 8 chars

    # filter and sort
    page.fill("#session-filter", "aaaa1111")
    assert page.locator("#sessions tr").count() == 1
    page.fill("#session-filter", "")
    page.select_option("#tier-filter", "high")
    assert page.locator("#sessions tr").count() >= 1
    page.select_option("#tier-filter", "")
    page.click("th[data-sort=score] button")
    scores = [float(t) for t in page.locator("#sessions tr td:nth-child(2)").all_inner_texts()]
    assert scores == sorted(scores, reverse=True) or scores == sorted(scores)
    first_direction = page.locator("th[data-sort=score]").get_attribute("aria-sort")
    page.click("th[data-sort=score] button")
    assert page.locator("th[data-sort=score]").get_attribute("aria-sort") != first_direction

    # timeline, playbook, linked sessions, report export
    page.locator("#sessions tr", has_text="198.51.100.9").get_by_role("button", name="Timeline").click()
    page.locator("#detail").wait_for()
    expect(page.locator("#timeline tr").first).to_be_visible()
    assert page.locator("#playbook li").count() >= 1
    assert page.locator("#facts").inner_text().count("Session id") == 1
    assert page.locator("#linked button").count() >= 1                   # the other session of the campaign
    assert "<img src=x" in page.locator("#timeline").inner_text()
    assert_inert(page)
    shot(page, f"console-{name}")
    with page.expect_download() as download:
        page.click("#report-md")
    text = Path(download.value.path()).read_text(encoding="utf-8")
    assert "aaaa1111" in text and "<img" not in text and "<script" not in text
    with page.expect_download() as download:
        page.click("#report-json")
    report = json.loads(Path(download.value.path()).read_text(encoding="utf-8"))
    assert report["session"]["id"] == "aaaa1111" and report["stages"]
    page.click("#detail-close")
    assert page.locator("#detail").is_hidden()

    # release button, confirmed server-side
    row = page.locator("#sessions tr", has_text="198.51.100.9")
    row.get_by_role("button", name="Release").click()
    page.locator("#sessions tr", has_text="198.51.100.9").get_by_role("button", name="Re-arm").wait_for()
    assert server.engine.sessions.get("aaaa1111").released is True
    assert "Released" in page.locator("#sessions tr", has_text="198.51.100.9").inner_text()
    watch.expect_clean()
    context.close()


def test_live_feed_gets_new_events_without_reload(browser, server):
    context, page, watch = new_page(browser, server)
    open_console(page, server)
    expect(page.locator("#sessions-state")).to_contain_text("No flagged sessions")     # empty state
    server.hit("/.env")
    page.locator("#feed tr", has_text="/.env").first.wait_for()
    page.locator("#sessions tr").first.wait_for()                                    # session list refreshed too
    assert_inert(page)
    page.fill("#feed-filter", "no-such-thing")
    expect(page.locator("#feed-state")).to_contain_text("No events match")
    page.fill("#feed-filter", "")
    page.check("#alerts-only")
    page.uncheck("#alerts-only")
    watch.expect_clean()
    context.close()


def test_error_state_has_retry(browser, server):
    server.seed()
    context, page, watch = new_page(browser, server)
    page.route("**/api/v1/sessions", lambda route: route.abort())
    open_console(page, server)
    page.locator("#sessions-state.error").wait_for()
    assert "Could not load sessions" in page.locator("#sessions-state").inner_text()
    page.unroute("**/api/v1/sessions")
    page.get_by_role("button", name="Retry").click()
    page.locator("#sessions tr").first.wait_for()
    context.close()


def test_settings_levels_validation_and_save(browser, server):
    context, page, watch = new_page(browser, server)
    open_console(page, server)
    expect(page.locator("#level-note")).not_to_be_empty()
    page.locator(".level", has_text="Heavy").click()
    expect(page.locator("#level-message")).to_contain_text("Level 4")
    assert server.call(lambda: server.config.tarpit.max_delay) > 0

    page.click("summary")
    # the browser's own limits stop bad values before any request is sent
    sent = []
    page.on("request", lambda r: r.method == "POST" and "settings" in r.url and sent.append(r.url))
    page.fill("#f-base", "9999")
    page.click("button:has-text('Save settings')")
    assert page.locator("#f-base").get_attribute("aria-invalid") == "true"
    assert page.locator("#f-base-error").inner_text().strip()
    assert not sent
    # a combination only the server can judge is refused with its message
    page.fill("#f-base", "1")
    page.fill("#f-medium", "90")
    page.fill("#f-high", "20")
    before = server.call(lambda: server.config.detection.trap_threshold)
    page.click("button:has-text('Save settings')")
    page.locator("#settings-message[data-kind=error]").wait_for()
    assert server.call(lambda: server.config.detection.trap_threshold) == before
    # and a valid change is saved
    page.fill("#f-medium", "30")
    page.fill("#f-high", "70")
    page.click("button:has-text('Save settings')")
    page.locator("#settings-message[data-kind=ok]").wait_for()
    assert server.call(lambda: server.config.detection.trap_threshold) == 70
    watch.expect_clean(allow=("400",))
    context.close()


def test_keyboard_navigation_and_focus(browser, server):
    server.seed()
    context, page, watch = new_page(browser, server)
    open_console(page, server)
    page.locator("#sessions tr").first.wait_for()
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.className") == "skip"
    seen = []
    for _ in range(60):
        page.keyboard.press("Tab")
        info = page.evaluate("""() => { const e = document.activeElement;
            const own = getComputedStyle(e);
            const next = e.type === 'radio' && e.nextElementSibling ? getComputedStyle(e.nextElementSibling) : own;
            const name = e.getAttribute('aria-label') || (e.labels && e.labels[0] && e.labels[0].textContent) ||
                         e.textContent || e.getAttribute('placeholder') || '';
            const ring = s => (s.outlineStyle !== 'none' && parseFloat(s.outlineWidth) > 0) || s.boxShadow !== 'none';
            return {tag: e.tagName, name: name.trim(), ring: ring(own) || ring(next), id: e.id}; }""")
        if info["tag"] == "BODY":
            break
        assert info["name"], info
        assert info["ring"], f"no visible focus on {info}"
        seen.append(info["id"] or info["name"])
    assert len(seen) > 15
    # sorting and opening the timeline work from the keyboard alone
    page.focus("th[data-sort=ip] button")
    page.keyboard.press("Enter")
    assert page.locator("th[data-sort=ip]").get_attribute("aria-sort") == "ascending"
    opener = page.locator("#sessions tr").first.get_by_role("button", name="Timeline")
    opener.focus()
    page.keyboard.press("Enter")
    page.locator("#detail").wait_for()
    assert page.evaluate("document.activeElement.id") == "detail-title"
    page.focus("#detail-close")
    page.keyboard.press("Enter")
    assert page.locator("#detail").is_hidden()
    assert page.evaluate("document.activeElement.tagName") == "BUTTON"       # back on the opener
    watch.expect_clean()
    context.close()


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_accessibility_contrast_labels_and_landmarks(browser, server, scheme):
    server.seed()
    context, page, watch = new_page(browser, server, scheme=scheme)
    open_console(page, server)
    page.locator("#sessions tr").first.wait_for()
    page.locator("#sessions tr").first.get_by_role("button", name="Timeline").click()
    expect(page.locator("#timeline tr").first).to_be_visible()
    page.click("summary")
    assert page.evaluate(CONTRAST) == []
    # every field and control has an accessible name; the document has a language and one h1
    assert page.evaluate("""() => [...document.querySelectorAll('input, select, button')].filter(e =>
        !(e.getAttribute('aria-label') || (e.labels && e.labels.length) || e.textContent.trim())).length""") == 0
    assert page.evaluate("document.documentElement.lang") == "en"
    assert page.locator("h1").count() == 1 and page.locator("main").count() == 1
    # severity is never colour alone: every badge carries its word
    assert all(t.strip() for t in page.locator(".badge").all_inner_texts())
    shot(page, f"accessibility-{scheme}")
    watch.expect_clean()
    context.close()


def test_mobile_layout_does_not_scroll_sideways(browser, server):
    server.seed()
    context, page, watch = new_page(browser, server, MOBILE)
    open_console(page, server)
    page.locator("#sessions tr").first.wait_for()
    wide = page.evaluate("""() => [...document.querySelectorAll('body *')].filter(e => !e.closest('.table-wrap') &&
        e.getBoundingClientRect().right > window.innerWidth + 1).map(e => e.tagName + '.' + e.className + '#' + e.id)""")
    assert wide == []
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    shot(page, "mobile-top")
    context.close()
