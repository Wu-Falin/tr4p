"""The tarpit seen from outside: real connections against the listener."""

import asyncio
import gzip
import time

import aiohttp

from tests.http_helpers import BROWSER, HOME_PAGE, ListenerCase


def agent(n: int) -> dict:
    """Headers of a distinct client (distinct header fingerprint)."""
    return dict(BROWSER, **{"User-Agent": f"Mozilla/5.0 (X11) Chrome/{100 + n}.0 Safari/537.36"})


class TarpitCase(ListenerCase):
    base = 0.3

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
        started = time.monotonic()
        response, body = await self.get(path, headers=headers, **kwargs)
        return response, body, time.monotonic() - started


class Delays(TarpitCase):
    async def test_clean_traffic_is_not_delayed(self):
        _, _, took = await self.timed("/", agent(1))
        self.assertLess(took, 0.25)
        self.assertEqual(self.app.tarpit.stats()["completed"], 0)

    async def test_trapped_session_waits_longer_each_time(self):
        headers = self.trapped()
        times = []
        for _ in range(4):
            response, body, took = await self.timed("/api/data", headers)
            self.assertEqual(response.status, 200)
            times.append(took)
        for took, expected in zip(times, (0.3, 0.6, 1.2, 2.4)):
            self.assertGreaterEqual(took, expected * 0.9)
            self.assertLess(took, expected + 0.6)
        stats = self.app.tarpit.stats()
        self.assertEqual(stats["completed"], 4)
        self.assertEqual(stats["held"], 0)
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
        started = time.monotonic()
        async with self.client.head(self.base + "/api/data", headers=headers) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(await response.read(), b"")
            self.assertGreater(int(response.headers["Content-Length"]), 0)
        self.assertGreaterEqual(time.monotonic() - started, 0.5)


class Drip(TarpitCase):
    def tune(self, config):
        config.public.upstream_connections = 1
        config.tarpit.base_delay = 2.0
        config.tarpit.max_delay = 2.0

    async def test_answer_trickles_and_finishes_at_the_end(self):
        started = time.monotonic()
        arrivals = []
        async with self.client.get(self.base + "/", headers=self.trapped()) as response:
            first_byte = time.monotonic() - started
            total = b""
            async for chunk in response.content.iter_any():
                arrivals.append(time.monotonic() - started)
                total += chunk
        self.assertIn(b"Real content.", total)
        self.assertEqual(int(response.headers["Content-Length"]), len(total))
        self.assertLess(first_byte, 1.0)                           # headers come early
        self.assertGreaterEqual(arrivals[-1], 1.8)                 # last piece at the very end
        self.assertGreaterEqual(len(arrivals), 4)
        gaps = [b - a for a, b in zip(arrivals, arrivals[1:])]
        self.assertLess(max(gaps), 0.6)                            # never silent for long

    async def test_site_connection_is_free_while_an_answer_is_held(self):
        # One connection to the site in total. If a held answer kept it, the
        # second client would have to wait for the whole delay.
        held = asyncio.ensure_future(self.timed("/", self.trapped()))
        await asyncio.sleep(0.6)
        self.assertEqual(self.app.tarpit.stats()["held"], 1)
        self.assertGreater(self.app.tarpit.stats()["buffered_bytes"], 0)
        _, body, took = await self.timed("/", agent(7))
        self.assertIn(b"Real content.", body)
        self.assertLess(took, 0.3)
        await held
        self.assertEqual(self.app.tarpit.stats()["buffered_bytes"], 0)

    async def test_compressed_answer_is_dripped_as_gzip(self):
        headers = dict(self.trapped(), **{"Accept-Encoding": "gzip, deflate, br"})
        response, body = await self.get("/", headers=headers)
        self.assertEqual(response.headers["Content-Encoding"], "gzip")
        self.assertIn("Accept-Encoding", response.headers["Vary"])
        self.assertIn(b"Real content.", gzip.decompress(body))

    async def test_memory_budget_falls_back_to_a_plain_pause(self):
        self.config.tarpit.buffer_total_bytes = 0
        _, body, took = await self.timed("/", self.trapped())
        self.assertIn(b"Real content.", body)
        self.assertGreaterEqual(took, 1.8)
        self.assertEqual(self.app.tarpit.stats()["buffered_bytes"], 0)


class Limits(TarpitCase):
    def tune(self, config):
        config.tarpit.base_delay = 1.0
        config.tarpit.max_delay = 1.0
        config.tarpit.session_concurrency = 1
        config.tarpit.session_queue = 1
        config.tarpit.max_sessions = 10

    async def test_parallel_requests_queue_then_get_refused_and_bumped(self):
        headers = self.trapped()
        await self.get("/", headers=headers)                       # trap it first
        session = next(s for s in self.engine.sessions.flagged() if s.tier == "high")
        phase = session.phase
        started = time.monotonic()
        results = await asyncio.gather(*(self.timed("/api/data", headers) for _ in range(3)))
        statuses = sorted(r[0].status for r in results)
        self.assertEqual(statuses, [200, 200, 503])
        refused = next(r for r in results if r[0].status == 503)
        self.assert_anonymous(refused[0], refused[1])
        self.assertGreaterEqual(time.monotonic() - started, 1.9)   # second waited for the first
        stats = self.app.tarpit.stats()
        self.assertEqual(stats["refused"], 1)
        self.assertEqual(stats["queued"], 0)
        self.assertGreaterEqual(session.phase, phase + 4)          # 3 requests + bumps

    async def test_hanging_up_early_counts_as_ignoring_the_delay(self):
        headers = self.trapped()
        await self.get("/", headers=headers)
        session = next(s for s in self.engine.sessions.flagged() if s.tier == "high")
        phase = session.phase
        try:
            await asyncio.wait_for(self.get("/api/data", headers=headers), 0.3)
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(0.3)
        stats = self.app.tarpit.stats()
        self.assertEqual(stats["abandoned"], 1)
        self.assertEqual(stats["held"], 0)
        self.assertEqual(session.phase, phase + 2)                 # the request itself + the bump
        self.assertIn("gave up waiting", self.sink.kinds("tarpit")[-1]["detail"])

    async def test_oldest_session_is_dropped_past_the_cap(self):
        async def hold(n):
            try:
                response, _ = await self.get("/", headers=self.trapped(n))
                return response.status
            except aiohttp.ClientError:
                return "dropped"

        tasks = []
        for n in range(12):
            tasks.append(asyncio.ensure_future(hold(n)))
            await asyncio.sleep(0.02)
        self.assertLessEqual(self.app.tarpit.stats()["sessions"], 10)
        results = await asyncio.gather(*tasks)
        self.assertEqual(results[:2], ["dropped", "dropped"])      # the two oldest
        self.assertEqual(results[2:], [200] * 10)
        stats = self.app.tarpit.stats()
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
        self.assertLess(took, 1.2)                                 # light_max_delay 0.6
        _, _, took = await self.timed("/static/app.css", headers)
        self.assertLess(took, 0.25)


class SelfProtection(ListenerCase):
    def configure(self, config):
        config.public.max_connections = 16
        config.public.idle_timeout = 1.0
        config.public.body_timeout = 1.0
        config.tarpit.enabled = True
        config.tarpit.base_delay = 5.0
        config.tarpit.max_delay = 5.0
        config.tarpit.jitter = 0.0

    async def connect(self):
        return await asyncio.open_connection("127.0.0.1", self.app.port)

    async def closed_within(self, reader, seconds) -> bool:
        try:
            return await asyncio.wait_for(reader.read(), seconds) is not None
        except asyncio.TimeoutError:
            return False

    async def test_connections_beyond_the_cap_are_refused(self):
        kept = [await self.connect() for _ in range(16)]
        await asyncio.sleep(0.1)
        self.assertEqual(self.app.open_connections, 16)
        reader, writer = await self.connect()
        self.assertTrue(await self.closed_within(reader, 1.0))
        self.assertEqual(self.app.refused_connections, 1)
        for _, w in kept + [(reader, writer)]:
            w.close()

    async def test_a_trapped_connection_is_dropped_to_make_room(self):
        secret = self.engine.honeytokens.value("api_key")
        reader, writer = await self.connect()
        writer.write(f"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: a\r\n"
                     f"Authorization: Bearer {secret}\r\n\r\n".encode())
        await writer.drain()
        await asyncio.sleep(0.2)
        self.assertEqual(self.app.tarpit.stats()["held"], 1)
        kept = [await self.connect() for _ in range(15)]
        await asyncio.sleep(0.1)
        newcomer = await self.connect()                            # 17th connection
        self.assertTrue(await self.closed_within(reader, 1.0))     # the trapped one went
        self.assertEqual(self.app.refused_connections, 0)
        self.assertEqual(self.app.tarpit.stats()["dropped"], 1)
        for _, w in kept + [newcomer, (reader, writer)]:
            w.close()
        await asyncio.sleep(0.1)
        response, body = await self.get("/")                       # and real traffic still works
        self.assertEqual(response.status, 200)

    async def test_connection_that_never_finishes_a_request_is_closed(self):
        reader, writer = await self.connect()
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ")
        await writer.drain()
        started = time.monotonic()
        self.assertTrue(await self.closed_within(reader, 3.0))
        self.assertGreaterEqual(time.monotonic() - started, 0.9)
        writer.close()

    async def test_idle_keep_alive_is_closed_but_a_busy_one_is_not(self):
        reader, writer = await self.connect()
        request = b"GET /api/data HTTP/1.1\r\nHost: x\r\nUser-Agent: b\r\nAccept: */*\r\n\r\n"
        for _ in range(3):                                         # active for 1.8 s
            writer.write(request)
            await writer.drain()
            self.assertIn(b"200 OK", await asyncio.wait_for(reader.read(4096), 2))
            await asyncio.sleep(0.6)
        self.assertTrue(await self.closed_within(reader, 3.0))     # then idle: closed
        writer.close()

    async def test_stalled_upload_is_cut_off(self):
        reader, writer = await self.connect()
        writer.write(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n"
                     b"Content-Length: 100000\r\n\r\npartial")
        await writer.drain()
        started = time.monotonic()
        self.assertTrue(await self.closed_within(reader, 4.0))
        self.assertLess(time.monotonic() - started, 3.5)
        writer.close()
        response, _ = await self.get("/")                          # the site connection was not leaked
        self.assertEqual(response.status, 200)


class WireDetails(ListenerCase):
    async def test_malformed_request_is_answered_as_http_1_1(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.app.port)
        writer.write(b"\x16\x03\x01 not http\r\n\r\n")
        await writer.drain()
        raw = (await asyncio.wait_for(reader.read(), 5)).decode("latin-1")
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
