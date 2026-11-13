"""Flood test: 2,000 trapped connections against the memory budget.

Runs the real service as a separate process, traps 2,000 distinct sessions
that all sit in the tarpit at once, and checks three things:

* memory stays inside the documented budget (250 MB);
* ordinary visitors are still served promptly during the flood;
* past the session cap, the oldest trapped connections are dropped.
"""

import asyncio
import os
import socket
import subprocess
import sys
import time
import unittest

from tr4p.config import Config
from tr4p.honeytoken import Honeytokens
from tr4p.seed import Seed

TRAPPED = 2000
EXTRA = 100
MEMORY_BUDGET_MB = 250
NEEDED_FILES = TRAPPED + EXTRA + 200


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def rss_mb(pid: int) -> float:
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)],
                         stdout=subprocess.PIPE, check=True).stdout
    return int(out.strip()) / 1024.0


def raise_file_limit() -> bool:
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = NEEDED_FILES * 2
    if soft >= wanted:
        return True
    target = wanted if hard == resource.RLIM_INFINITY else min(wanted, hard)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except (ValueError, OSError):
        return False
    return target >= NEEDED_FILES + 64


@unittest.skipIf(sys.platform == "win32", "memory is measured with ps; covered on Linux and macOS")
class Flood(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import tempfile
        from pathlib import Path

        if not raise_file_limit():
            self.skipTest("cannot raise the open-file limit far enough")
        self.tmp = tempfile.TemporaryDirectory()
        home = Path(self.tmp.name)
        config = Config()
        config.public.mode = "standalone"
        config.public.host = "127.0.0.1"
        config.public.port = self.port = free_port()
        config.public.idle_timeout = 120.0
        config.dashboard.port = free_port()
        config.tarpit.base_delay = 45.0          # hold everything for the whole test
        config.tarpit.max_delay = 45.0
        config.tarpit.light_max_delay = 45.0
        config.tarpit.jitter = 0.0
        config.tarpit.max_sessions = TRAPPED
        config.save(home / "config.json")
        seed = Seed.generate()
        seed.save(home / "secret.key")
        self.secret = Honeytokens(seed).value("api_key")
        self.server = subprocess.Popen(
            [sys.executable, "-m", "tr4p", "--home", str(home), "run"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(100):
            try:
                _, writer = await asyncio.open_connection("127.0.0.1", self.port)
                writer.close()
                break
            except OSError:
                await asyncio.sleep(0.1)
        else:
            self.fail("service did not start")
        self.writers = []

    async def asyncTearDown(self):
        for writer in self.writers:
            writer.close()
        self.server.terminate()
        try:
            self.server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.server.kill()
        self.tmp.cleanup()

    async def trap(self, number: int):
        """Open a connection whose request uses a planted secret: trapped at once."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(
            f"GET / HTTP/1.1\r\nHost: flood.example\r\nUser-Agent: Mozilla/5.0 Chrome/{number}\r\n"
            f"Accept: text/html\r\nAccept-Language: en\r\nAccept-Encoding: identity\r\n"
            f"Authorization: Bearer {self.secret}\r\n\r\n".encode()
        )
        await writer.drain()
        self.writers.append(writer)
        return reader

    async def clean_request(self) -> float:
        started = time.monotonic()
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(b"GET /about HTTP/1.1\r\nHost: flood.example\r\nUser-Agent: Mozilla/5.0 "
                     b"Chrome/1 Safari/1\r\nAccept: text/html\r\nAccept-Language: en\r\n"
                     b"Accept-Encoding: identity\r\nConnection: close\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), 10)
        writer.close()
        self.assertIn(b"200 OK", data[:20])
        self.assertIn(b"</html>", data)
        return time.monotonic() - started

    @staticmethod
    async def is_closed(reader) -> bool:
        """True when the server has closed this connection."""
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), 0.3)
                if not chunk:
                    return True
        except asyncio.TimeoutError:
            return False
        except ConnectionError:
            return True

    async def count_closed(self, readers) -> int:
        return sum(await asyncio.gather(*(self.is_closed(reader) for reader in readers)))

    async def test_two_thousand_trapped_connections_stay_within_budget(self):
        idle = rss_mb(self.server.pid)
        readers = []
        for start in range(0, TRAPPED, 200):
            readers += await asyncio.gather(*(self.trap(n) for n in range(start, start + 200)))
        await asyncio.sleep(4)                      # let every hold reach its drip stage

        self.assertEqual(await self.count_closed(readers), 0)   # all are still being held
        loaded = rss_mb(self.server.pid)
        latency = max([await self.clean_request() for _ in range(5)])
        print(f"\nflood: idle {idle:.0f} MB, {TRAPPED} held connections {loaded:.0f} MB, "
              f"clean request during flood {latency * 1000:.0f} ms")
        self.assertLess(loaded, MEMORY_BUDGET_MB)
        self.assertLess(latency, 1.0)

        # Past the cap: each new trapped session pushes out the oldest one.
        newcomers = await asyncio.gather(*(self.trap(TRAPPED + n) for n in range(EXTRA)))
        await asyncio.sleep(2)
        self.assertEqual(await self.count_closed(readers[:EXTRA]), EXTRA)    # oldest: gone
        self.assertEqual(await self.count_closed(readers[EXTRA:]), 0)        # the rest: held
        self.assertEqual(await self.count_closed(newcomers), 0)              # newcomers: held
        self.assertLess(rss_mb(self.server.pid), MEMORY_BUDGET_MB)
        self.assertLess(await self.clean_request(), 1.0)
        self.assertIsNone(self.server.poll())       # still running
