"""Regression tests for the findings of the pre-release security review."""

import asyncio
import ipaddress
import re
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import make_seed
from tests.http_helpers import ListenerCase
from tests.test_dashboard import POST, DashboardCase
from tr4p.alerts import is_public_address
from tr4p.decoylink import DecoyLink
from tr4p.honeytoken import Honeytokens

ROOT = Path(__file__).resolve().parents[1]


class ParallelLogins(DashboardCase):
    async def test_parallel_guesses_cannot_outrun_the_limiter(self):
        async def guess():
            response, _ = await self.call("POST", "/api/v1/login", {"password": "wrong password!!"}, POST)
            return response.status

        statuses = await asyncio.gather(*(guess() for _ in range(30)))
        self.assertEqual(statuses.count(401), 5)          # the per-address limit, exactly
        self.assertEqual(statuses.count(429), 25)


class DecoyPeerRefused(DashboardCase):
    async def test_dashboard_refuses_the_decoy_address(self):
        self.dashboard._refused_peers = lambda: frozenset({"127.0.0.1"})
        for method, path in (("GET", "/login"), ("GET", "/api/v1/state"), ("POST", "/api/v1/login")):
            response, _ = await self.call(method, path, {"password": "x"} if method == "POST" else None, POST)
            self.assertEqual(response.status, 403, path)


class DecoyAddresses(unittest.IsolatedAsyncioTestCase):
    async def test_decoy_addresses_never_include_loopback(self):
        link = DecoyLink.__new__(DecoyLink)
        link._remote, link.peer_addresses = "http://decoy:8081", frozenset()
        peer = str(_v4(172, 20, 0, 3))
        infos = [(2, 1, 6, "", (peer, 0)), (2, 1, 6, "", ("127.0.0.1", 0)),
                 (10, 1, 6, "", ("::1", 0, 0, 0))]
        loop = asyncio.get_running_loop()
        with mock.patch.object(loop, "getaddrinfo", mock.AsyncMock(return_value=infos)):
            await link.refresh_peers()
        self.assertEqual(link.peer_addresses, frozenset({peer}))


def _v4(*octets):
    return ipaddress.IPv4Address(bytes(octets))


def _v6(prefix, v4, shift=0):
    return str(ipaddress.IPv6Address(prefix | (int(v4) << shift)))


def test_ipv4_inside_ipv6_is_judged_by_the_ipv4_address():
    loop, private, metadata, public = _v4(127, 0, 0, 1), _v4(10, 0, 0, 1), _v4(169, 254, 169, 254), _v4(8, 8, 8, 8)
    nat64, mapped, sixtofour = 0x0064FF9B << 96, 0xFFFF << 32, 0x2002 << 112
    for address in (_v6(0, loop), _v6(mapped, loop), _v6(nat64, loop), _v6(nat64, metadata),
                    _v6(nat64, private), _v6(sixtofour, loop, 80), _v6(sixtofour, private, 80)):
        assert not is_public_address(address), address
    for address in (_v6(nat64, public), str(public), _v6(0x26064700 << 96, _v4(0, 0, 17, 17))):
        assert is_public_address(address), address


def test_shared_token_id_links_to_no_session():
    tokens = Honeytokens(make_seed())
    spec = tokens._by_name["jwt_secret"]
    seen = {}
    for n in range(20000):
        ident = tokens._marker(spec, f"s{n}")[0]
        if ident in seen:
            first, second = seen[ident], f"s{n}"
            break
        seen[ident] = f"s{n}"
    issued = tokens.issue("jwt_secret", first)
    assert tokens.find(issued).origin == first
    tokens.issue("jwt_secret", second)
    found = tokens.find(issued)
    assert found.name == "jwt_secret" and found.origin is None   # still planted, but no false link
    tokens.issue("jwt_secret", first)
    assert tokens.find(issued).origin is None                    # stays ambiguous


class BaitIsNeverCached(ListenerCase):
    async def test_bait_with_session_secrets_is_marked_no_store(self):
        response, body = await self.get("/.env")
        self.assertEqual(response.status, 200)
        self.assertIn(b"DB_PASSWORD", body)
        self.assertEqual(response.headers["Cache-Control"], "no-store")


def test_runtime_dependency_floor_excludes_known_parser_flaws():
    aiohttp = re.search(r'"(aiohttp[^"]*)"', (ROOT / "pyproject.toml").read_text()).group(1)
    floor = tuple(int(x) for x in re.search(r">=([\d.]+)", aiohttp).group(1).split("."))
    assert floor >= (3, 14, 4), aiohttp


def test_base_image_is_pinned_by_digest():
    froms = re.findall(r"^FROM (\S+)", (ROOT / "Dockerfile").read_text(), re.M)
    assert froms and all(re.search(r"@sha256:[0-9a-f]{64}$", image) for image in froms), froms


def test_workflows_are_least_privilege_and_pinned():
    workflows = list((ROOT / ".github" / "workflows").glob("*.y*ml"))
    assert workflows
    for path in workflows:
        text = path.read_text()
        assert "pull_request_target" not in text, path
        assert re.search(r"^permissions:\n  contents: read\n", text, re.M), path
        assert not re.search(r"^ {4,}permissions:", text, re.M), path       # no job widens it
        assert not re.search(r"write-all|: write\b", text), path
        uses = re.findall(r"uses: (\S+)", text)
        assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u) for u in uses), uses
        checkouts = text.count("uses: actions/checkout@")
        assert re.findall(r"uses: actions/checkout@\S+.*\n\s+with:(?:\n\s+[\w-]+: .*)*?\n\s+persist-credentials: false",
                          text) and text.count("persist-credentials: false") == checkouts, path
