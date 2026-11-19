"""The tarpit seen from outside: real connections against the listener.

Pauses run on a fake clock (tests/helpers.FakeTime), so what is asserted is
what the tarpit *asked for*, never how long a machine took to wait. Tests
that must observe a request while it is held close a gate and look at the
tarpit's state, then open it. The self-protection tests exercise real socket
timers and assert lower bounds only; their timeouts are hang guards."""

import asyncio
import gzip
import time

import aiohttp

from tests.helpers import FakeTime, eventually
from tests.http_helpers import BROWSER, ListenerCase
from tr4p.tarpit import Tarpit


def agent(n: int) -> dict:
    """Headers of a distinct client (distinct header fingerprint)."""
    return dict(BROWSER, **{"User-Agent": f"Mozilla/5.0 (X11) Chrome/{100 + n}.0 Safari/537.36"})


class TarpitCase(ListenerCase):
    async def asyncSetUp(self):
        self.time = FakeTime()
        await super().asyncSetUp()

    def make_tarpit(self):
        return Tarpit(self.config.tarpit, self.engine.bump, clock=self.time.clock,
                      account=self.engine.account_hold, sleep=self.time.sleep)

    def configure(self, config):
        pit = config.tarpit
        pit.enabled = True
        pit.jitter = 0.0
        pit.base_delay = 0.3
        pit.max_delay = 2.4
        pit.light_max_delay = 0.6
        pit.phase_requests = 1
        pit.drip_interval = 0.2
        self.tune(config)

    def tune(self, config):
        """Per-class adjustments."""

    def trapped(self, n: int = 0) -> dict:
        secret = self.engine.honeytokens.value("api_key")
        return dict(agent(n), Authorization=f"Bearer {secret}")

    async def timed(self, path, headers, **kwargs):
        """Like get, plus the pause the tarpit asked for (fake seconds)."""
        before = self.time.now
        response, body = await self.get(path, headers=headers, **kwargs)
        return response, body, self.time.now - before

    def stats(self):
        return self.app.tarpit.stats()

    def assert_close(self, took, expected):
        """Drip pauses carry up to 10% jitter on their gaps."""
        self.assertGreaterEqual(took, expected * 0.9 - 1e-9)
        self.assertLessEqual(took, expected * 1.1 + 1e-9)


class Delays(TarpitCase):
    async def test_clean_traffic_is_not_delayed(self):
        _, _, took = await self.timed("/", agent(1))
        self.assertEqual((took, self.time.sleeps), (0, []))
        self.assertEqual(self.stats()["completed"], 0)

    async def test_trapped_session_waits_longer_each_time(self):
        headers = self.trapped()
        for expected in (0.3, 0.6, 1.2, 2.4):
            response, body, took = await self.timed("/api/data", headers)
            self.assertEqual(response.status, 200)
            self.assert_close(took, expected)
        stats = self.stats()
        self.assertEqual((stats["completed"], stats["held"]), (4, 0))
        self.assertGreaterEqual(stats["burned_seconds"], 4.0)

    async def test_answer_is_intact_and_cookie_moves_along_the_chain(self):
        headers = self.trapped()
        first, body = await self.get("/", headers=headers)
        self.assertIn(b"Real content.", body)
        name = self.persona.cookie_name
        value = first.headers["Set-Cookie"].split(";")[0].split("=", 1)[1]
        second, _ = await self.get("/", headers=dict(headers, Cookie=f"{name}={value}"))
        rolled = second.headers["Set-Cookie"].split(";")[0].split("=", 1)[1]
        self.assertNotEqual(rolled, value)
        self.assertEqual(self.engine.read_cookie(rolled)[1], 2)
        self.assert_anonymous(second, b"")

    async def test_head_and_empty_answers_are_delayed_too(self):
        headers = self.trapped()
        await self.get("/", headers=headers)                      # phase 0 -> 1
        before = self.time.now
        async with self.client.head(self.base + "/api/data", headers=headers) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(await response.read(), b"")
            self.assertGreater(int(response.headers["Content-Length"]), 0)
        self.assert_close(self.time.now - before, 0.6)


class Drip(TarpitCase):
    def tune(self, config):
        config.public.upstream_connections = 1
        config.tarpit.base_delay = 2.0
        config.tarpit.max_delay = 2.0

    async def test_answer_trickles_and_finishes_at_the_end(self):
        before = len(self.time.sleeps)
        response, total = await self.get("/", headers=self.trapped())
        schedule = self.time.sleeps[before:]
        self.assertIn(b"Real content.", total)
        self.assertEqual(int(response.headers["Content-Length"]), len(total))
        self.assert_close(sum(schedule), 2.0)                      # the last piece is at the very end
        self.assertGreaterEqual(len(schedule), 4)                  # a drip, not one long pause
        self.assertLessEqual(schedule[0], 0.2)                     # headers come early
        self.assertLess(max(schedule[1:]), 0.6)                    # never silent for long

    async def test_site_connection_is_free_while_an_answer_is_held(self):
        # One connection to the site in total. If a held answer kept it, the
        # second client would wait for the whole hold and never finish.
        self.time.gate, self.time.gate_after = asyncio.Event(), 1   # hold after the first pause
        held = asyncio.ensure_future(self.get("/", headers=self.trapped()))
        await eventually(lambda: self.stats()["buffered_bytes"] > 0, "answer buffered")
        self.assertEqual(self.stats()["held"], 1)
        _, body = await asyncio.wait_for(self.get("/", headers=agent(7)), 30)
        self.assertIn(b"Real content.", body)
        self.assertFalse(held.done())                              # still held when the other finished
        self.time.gate.set()
        await held
        self.assertEqual(self.stats()["buffered_bytes"], 0)

    async def test_compressed_answer_is_dripped_as_gzip(self):
        headers = dict(self.trapped(), **{"Accept-Encoding": "gzip, deflate, br"})
        response, body = await self.get("/", headers=headers)
        self.assertEqual(response.headers["Content-Encoding"], "gzip")
        self.assertIn("Accept-Encoding", response.headers["Vary"])
        self.assertIn(b"Real content.", gzip.decompress(body))

    async def test_memory_budget_falls_back_to_a_plain_pause(self):
        self.config.tarpit.buffer_total_bytes = 0
        before = len(self.time.sleeps)
        _, body = await self.get("/", headers=self.trapped())
        self.assertIn(b"Real content.", body)
        self.assertEqual(self.time.sleeps[before:], [2.0])         # one pause, nothing buffered
        self.assertEqual(self.stats()["buffered_bytes"], 0)


class Limits(TarpitCase):
    def tune(self, config):
        config.tarpit.base_delay = 1.0
        config.tarpit.max_delay = 1.0
        config.tarpit.session_concurrency = 1
        config.tarpit.session_queue = 1
        config.tarpit.max_sessions = 10

    def session(self):
        return next(s for s in self.engine.sessions.flagged() if s.tier == "high")

    async def test_parallel_requests_queue_then_get_refused_and_bumped(self):
        headers = self.trapped()
        await self.get("/", headers=headers)                       # trap it first
        session = self.session()
        phase = session.phase
        self.time.gate = asyncio.Event()
        tasks = [asyncio.ensure_future(self.get("/api/data", headers=headers)) for _ in range(3)]
        await eventually(lambda: (self.stats()["held"], self.stats()["queued"], self.stats()["refused"])
                         == (1, 1, 1), "one held, one queued, one refused")
        self.time.gate.set()
        results = await asyncio.gather(*tasks)
        self.assertEqual(sorted(r[0].status for r in results), [200, 200, 503])
        refused = next(r for r in results if r[0].status == 503)
        self.assert_anonymous(*refused)
        stats = self.stats()
        self.assertEqual((stats["refused"], stats["queued"]), (1, 0))
        self.assertGreaterEqual(session.phase, phase + 4)          # 3 requests + bumps

    async def test_hanging_up_early_counts_as_ignoring_the_delay(self):
        headers = self.trapped()
        await self.get("/", headers=headers)
        session = self.session()
        phase = session.phase
        self.time.gate = asyncio.Event()
        task = asyncio.ensure_future(self.get("/api/data", headers=headers))
        await eventually(lambda: self.stats()["held"] == 1, "request held")
        task.cancel()                                              # the client gives up
        await eventually(lambda: self.stats()["abandoned"] == 1 and self.stats()["held"] == 0,
                         "hang-up noticed")
        self.assertEqual(session.phase, phase + 2)                 # the request itself + the bump
        self.assertIn("gave up waiting", self.sink.kinds("tarpit")[-1]["detail"])
        self.time.gate.set()

    async def test_oldest_session_is_dropped_past_the_cap(self):
        async def hold(n):
            # A raw connection: an HTTP client library may quietly retry a
            # dropped GET, which would add sessions the test did not start.
            head = "".join(f"{name}: {value}\r\n" for name, value in self.trapped(n).items())
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", self.app.port)
                writer.write(f"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{head}\r\n".encode())
                await writer.drain()
                data = await reader.read()
                writer.close()
            except ConnectionError:
                return "dropped"
            return int(data[9:12]) if data else "dropped"

        self.time.gate = asyncio.Event()
        tasks = []
        for n in range(12):
            tasks.append(asyncio.ensure_future(hold(n)))
            # Wait until the server has taken this session in before sending
            # the next, so "oldest" is the order the clients were started in.
            await eventually(lambda n=n: self.stats()["sessions"] + self.stats()["dropped"] == n + 1,
                             f"session {n} taken in")
        self.assertLessEqual(self.stats()["sessions"], 10)
        self.time.gate.set()
        results = await asyncio.gather(*tasks)
        self.assertEqual(results[:2], ["dropped", "dropped"])      # the two oldest
        self.assertEqual(results[2:], [200] * 10)
        stats = self.stats()
        self.assertEqual(stats["dropped"], 2)
        self.assertEqual(stats["abandoned"], 0)                    # a drop is not the client's doing
        self.assertEqual((stats["held"], stats["sessions"]), (0, 0))


class Medium(TarpitCase):
    async def test_light_tarpit_is_capped_and_spares_assets(self):
        headers = {"User-Agent": "curl/8.5.0", "Accept": "*/*"}
        canary = self.engine.canaries.current().link_paths[0]
        await self.get(canary, headers=headers)                    # canary + client = medium
        for _ in range(3):
            _, _, took = await self.timed("/api/data", headers)
        self.assertGreaterEqual(took, 0.5)
        self.assertLessEqual(took, 0.6 * 1.1 + 1e-9)               # light_max_delay 0.6
        _, _, took = await self.timed("/static/app.css", headers)
        self.assertEqual(took, 0)                                  # assets are spared


class SelfProtection(ListenerCase):
    """Real sockets and real timers: only lower bounds are asserted; the
    timeouts below are hang guards."""

    def configure(self, config):
        config.public.max_connections = 16
        config.public.idle_timeout = 1.0
        config.public.body_timeout = 1.0
        config.tarpit.enabled = True
        config.tarpit.base_delay = 60.0
        config.tarpit.max_delay = 60.0
        config.tarpit.jitter = 0.0

    async def connect(self):
        return await asyncio.open_connection("127.0.0.1", self.app.port)

    async def closed_within(self, reader, seconds=15.0) -> bool:
        try:
            return await asyncio.wait_for(reader.read(), seconds) is not None
        except asyncio.TimeoutError:
            return False

    async def test_connections_beyond_the_cap_are_refused(self):
        kept = [await self.connect() for _ in range(16)]
        await eventually(lambda: self.app.open_connections == 16, "16 connections open")
        reader, writer = await self.connect()
        self.assertTrue(await self.closed_within(reader))
        self.assertEqual(self.app.refused_connections, 1)
        for _, w in kept + [(reader, writer)]:
            w.close()

    async def test_a_trapped_connection_is_dropped_to_make_room(self):
        secret = self.engine.honeytokens.value("api_key")
        reader, writer = await self.connect()
        writer.write(f"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: a\r\n"
                     f"Authorization: Bearer {secret}\r\n\r\n".encode())
        await writer.drain()
        await eventually(lambda: self.app.tarpit.stats()["held"] == 1, "request held")
        kept = [await self.connect() for _ in range(15)]
        await eventually(lambda: self.app.open_connections == 16, "16 connections open")
        newcomer = await self.connect()                            # 17th connection
        self.assertTrue(await self.closed_within(reader))          # the trapped one went
        self.assertEqual(self.app.refused_connections, 0)
        self.assertEqual(self.app.tarpit.stats()["dropped"], 1)
        for _, w in kept + [newcomer, (reader, writer)]:
            w.close()
        await eventually(lambda: self.app.open_connections == 0, "connections closed")
        response, body = await self.get("/")                       # and real traffic still works
        self.assertEqual(response.status, 200)

    async def test_connection_that_never_finishes_a_request_is_closed(self):
        reader, writer = await self.connect()
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ")
        await writer.drain()
        started = time.monotonic()
        self.assertTrue(await self.closed_within(reader))
        self.assertGreaterEqual(time.monotonic() - started, 0.9)   # waited for the idle timeout
        writer.close()

    async def test_idle_keep_alive_is_closed_but_a_busy_one_is_not(self):
        reader, writer = await self.connect()
        request = b"GET /api/data HTTP/1.1\r\nHost: x\r\nUser-Agent: b\r\nAccept: */*\r\n\r\n"
        for _ in range(8):             # active for 1.6 s, longer than the 1 s idle timeout
            writer.write(request)
            await writer.drain()
            self.assertIn(b"200 OK", await asyncio.wait_for(reader.read(4096), 30))
            await asyncio.sleep(0.2)   # well inside the idle timeout, even on a slow machine
        self.assertTrue(await self.closed_within(reader))          # then idle: closed
        writer.close()

    async def test_stalled_upload_is_cut_off(self):
        reader, writer = await self.connect()
        writer.write(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n"
                     b"Content-Length: 100000\r\n\r\npartial")
        await writer.drain()
        started = time.monotonic()
        self.assertTrue(await self.closed_within(reader))
        self.assertGreaterEqual(time.monotonic() - started, 0.9)   # waited for the body timeout
        writer.close()
        response, _ = await self.get("/")                          # the site connection was not leaked
        self.assertEqual(response.status, 200)


class WireDetails(ListenerCase):
    async def test_malformed_request_is_answered_as_http_1_1(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.app.port)
        writer.write(b"\x16\x03\x01 not http\r\n\r\n")
        await writer.drain()
        raw = (await asyncio.wait_for(reader.read(), 30)).decode("latin-1")
        writer.close()
        self.assertTrue(raw.startswith("HTTP/1.1 400 Bad Request\r\n"), raw[:40])
        self.assertIn("connection: close", raw.lower())

    async def test_compression_is_gzip_even_when_deflate_is_offered_first(self):
        headers = dict(BROWSER, **{"Accept-Encoding": "deflate, gzip, br"})
        response, body = await self.get("/", headers=headers)
        self.assertEqual(response.headers["Content-Encoding"], "gzip")
        self.assertIn(b"Real content.", gzip.decompress(body))
        self.assertTrue(response.headers["ETag"].startswith('W/"'))
        plain, body = await self.get("/", headers=dict(BROWSER, **{"Accept-Encoding": "deflate"}))
        self.assertNotIn("Content-Encoding", plain.headers)
        self.assertIn(b"Real content.", body)
