import random
from html.parser import HTMLParser

from tests.helpers import Clock, make_seed
from tr4p.canary import Canaries
from tr4p.inject import build_snippet, can_inject, inject, merge_robots
from tr4p.seed import Seed


class Audit(HTMLParser):
    """Checks that everything in a snippet is hidden from people."""

    def __init__(self):
        super().__init__()
        self.stack = []
        self.problems = []
        self.links = []

    def _hidden(self):
        return any(hidden for _, hidden in self.stack)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        hidden = tag in ("template", "script") or (
            "hidden" in attrs
            and attrs.get("aria-hidden") == "true"
            and "display:none" in attrs.get("style", "")
        )
        self.stack.append((tag, hidden))
        if tag == "script" and attrs.get("type") != "application/json":
            self.problems.append("executable script")
        if tag == "a":
            self.links.append(attrs)
            if not self._hidden():
                self.problems.append("visible link")
            if attrs.get("tabindex") != "-1":
                self.problems.append("link reachable by keyboard")
            if "nofollow" not in attrs.get("rel", ""):
                self.problems.append("link without nofollow")
            if attrs.get("aria-hidden") != "true":
                self.problems.append("link exposed to screen readers")

    def handle_endtag(self, tag):
        while self.stack:
            name, _ = self.stack.pop()
            if name == tag:
                break

    def handle_data(self, data):
        if data.strip() and not self._hidden():
            self.problems.append(f"visible text: {data.strip()[:40]}")


def snippet_for(seed_byte=7, page="/", links=2):
    seed = Seed(bytes([seed_byte]) * 32)
    canaries = Canaries(seed, clock=Clock())
    current = canaries.current()
    token = canaries.instruction_token("session")
    return build_snippet(current, token, seed.rng("inject", page), links), current, token


def test_snippets_are_invisible_to_people_and_assistive_tech():
    for seed_byte in range(1, 60):
        for page in ("/", "/about", "/products/1"):
            snippet, _, _ = snippet_for(seed_byte, page)
            audit = Audit()
            audit.feed(snippet.decode("ascii"))
            assert audit.problems == [], (seed_byte, page, audit.problems)
            assert b"onclick" not in snippet and b"javascript:" not in snippet


def test_snippet_contains_every_lure():
    snippet, current, token = snippet_for(links=2)
    text = snippet.decode("ascii")
    assert f"{current.instruction_path}?ref={token}" in text
    assert sum(path in text for path in current.link_paths) >= 2
    assert any(path in text for path in current.comment_paths)
    assert "<!--" in text


def test_snippet_is_ascii_and_stable_per_page():
    first, _, _ = snippet_for(page="/a")
    again, _, _ = snippet_for(page="/a")
    other, _, _ = snippet_for(page="/b")
    assert first == again
    assert first != other
    first.decode("ascii")


def test_snippet_respects_link_count():
    snippet, current, _ = snippet_for(links=0)
    audit = Audit()
    audit.feed(snippet.decode("ascii"))
    assert audit.links == []


def test_inject_goes_before_the_last_closing_body():
    page = b"<html><body><p>one</p></BODY></html>"
    result = inject(page, b"[X]")
    assert result == b"<html><body><p>one</p>[X]</BODY></html>"
    twice = b"<body>a</body><body>b</body>"
    assert inject(twice, b"[X]") == b"<body>a</body><body>b[X]</body>"


def test_inject_refuses_fragments():
    assert inject(b"<div>no body tag</div>", b"[X]") is None
    assert inject(b"", b"[X]") is None


def test_inject_keeps_every_original_byte():
    page = b"<html><body>" + bytes(range(256)) * 300 + b"</body></html>"
    result = inject(page, b"[X]")
    assert result.replace(b"[X]", b"", 1) == page


def test_can_inject_only_plain_html():
    assert can_inject("text/html", b"<html>")
    assert can_inject("TEXT/HTML; charset=UTF-8", b"<html>")
    assert not can_inject("application/json", b"{}")
    assert not can_inject("text/html; charset=utf-16", b"")
    assert not can_inject("text/html", b"\xff\xfe<\x00h\x00")
    assert not can_inject("", b"<html>")


def test_merge_robots_without_upstream():
    assert merge_robots(None, ("/a/", "/b/")) == "User-agent: *\nDisallow: /a/\nDisallow: /b/\n"
    assert merge_robots("  \n", ("/a/",)).startswith("User-agent: *\n")


def test_merge_robots_extends_existing_wildcard_group():
    upstream = "User-agent: *\nDisallow: /private/\n\nUser-agent: other\nDisallow: /\n"
    merged = merge_robots(upstream, ("/a/",))
    lines = merged.splitlines()
    assert lines[:3] == ["User-agent: *", "Disallow: /a/", "Disallow: /private/"]
    assert "User-agent: other" in lines and merged.count("User-agent: *") == 1


def test_merge_robots_adds_group_when_missing():
    merged = merge_robots("User-agent: special\nDisallow: /x\n", ("/a/",))
    assert merged.endswith("\n\nUser-agent: *\nDisallow: /a/\n")
    assert merged.startswith("User-agent: special\nDisallow: /x\n")


def test_merge_robots_handles_stacked_agents_and_comments():
    upstream = "User-Agent: * # everyone\nUser-agent: other\nAllow: /\n"
    lines = merge_robots(upstream, ("/a/",)).splitlines()
    assert lines == ["User-Agent: * # everyone", "User-agent: other", "Disallow: /a/", "Allow: /"]
