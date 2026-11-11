import asyncio
import gzip
import json

import aiohttp

import tr4p.public
from tests.http_helpers import BROWSER, HOME_PAGE, ListenerCase


class ProxyPassThrough(ListenerCase):
    async def test_page_is_served_with_hidden_tripwires(self):
        response, body = await self.get("/")
        current = self.engine.canaries.current()
        self.assertEqual(response.status, 200)
        self.assertIn(b"<h1>Welcome</h1><p>Real content.</p>", body)
        self.assertIn(current.instruction_path.encode(), body)
        self.assertTrue(any(path.encode() in body for path in current.link_paths))
        self.assertTrue(body.endswith(b"</body></html>"))
        self.assertEqual(int(response.headers["Content-Length"]), len(body))
        self.assertEqual(response.headers["ETag"], 'W/"abc123"')
        self.assertEqual(response.headers["Server"], "gunicorn")
        self.assertEqual(self.sink.events, [])
        self.assert_anonymous(response, body)

    async def test_non_html_is_byte_identical(self):
        response, body = await self.get("/api/data", headers=dict(BROWSER, Accept="*/*"))
        self.assertEqual(json.loads(body), {"ok": True, "items": [1, 2, 3]})
        self.assertNotIn(b"hidden", body)

    async def test_fragment_gzip_and_wide_pages_are_untouched(self):
        _, body = await self.get("/fragment")
        self.assertEqual(body, b"<div>partial</div>")
        response, body = await self.get("/gz")
        self.assertEqual(response.headers["Content-Encoding"], "gzip")
        self.assertEqual(gzip.decompress(body), HOME_PAGE)
        _, body = await self.get("/wide")
        self.assertEqual(body, HOME_PAGE.decode().encode("utf-16"))

    async def test_injected_page_is_compressed_when_client_accepts(self):
        response, body = await self.get("/", headers=dict(BROWSER, **{"Accept-Encoding": "gzip"}))
        self.assertEqual(response.headers.get("Content-Encoding"), "gzip")
        page = gzip.decompress(body)
        self.assertIn(b"Real content.", page)
        self.assertIn(self.engine.canaries.current().instruction_path.encode(), page)

    async def test_injection_failure_serves_original_page(self):
        def explode(*args, **kwargs):
            raise RuntimeError("boom")

        original = tr4p.public.build_snippet
        tr4p.public.build_snippet = explode
        try:
            with self.assertLogs("tr4p.public", level="ERROR"):
                response, body = await self.get("/")
        finally:
            tr4p.public.build_snippet = original
        self.assertEqual(response.status, 200)
        self.assertEqual(body, HOME_PAGE)

    async def test_xhr_style_requests_are_not_injected(self):
        _, body = await self.get("/", headers=dict(BROWSER, Accept="application/json"))
        self.assertEqual(body, HOME_PAGE)

    async def test_redirects_are_passed_on_not_followed(self):
        response, _ = await self.get("/redirect")
        self.assertEqual(response.status, 302)
        self.assertEqual(response.headers["Location"], "/elsewhere")

    async def test_head_request(self):
        async with self.client.head(self.base + "/", headers=BROWSER) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(await response.read(), b"")

    async def test_upstream_headers_and_cookies_survive(self):
        response, _ = await self.get("/cookies")
        cookies = response.headers.getall("Set-Cookie")
        self.assertIn("app_session=one; Path=/", cookies)
        self.assertIn("theme=dark; Path=/", cookies)
        self.assertEqual(len(cookies), 3)

    async def test_forwarded_request_headers(self):
        cookie_name = self.persona.cookie_name
        headers = dict(BROWSER, Cookie=f"app=1; {cookie_name}={self.engine.mint_cookie()}; b=2",
                       Accept="application/json", **{"X-Custom": "kept"})
        async with self.client.post(self.base + "/echo?a=1&b=%20x", data=b"k=v",
                                    headers=headers) as response:
            seen = json.loads(await response.read())
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["size"], 3)
        self.assertEqual(seen["raw_path"], "/echo?a=1&b=%20x")
        self.assertEqual(seen["headers"]["cookie"], "app=1; b=2")
        self.assertEqual(seen["headers"]["x-custom"], "kept")
        self.assertEqual(seen["headers"]["x-forwarded-for"], "127.0.0.1")
        self.assertEqual(seen["headers"]["x-forwarded-proto"], "http")
        self.assertEqual(seen["headers"]["host"], f"127.0.0.1:{self.app.port}")
        self.assertEqual(seen["headers"]["user-agent"], BROWSER["User-Agent"])

    async def test_client_without_user_agent_gets_none_invented(self):
        async with self.client.get(self.base + "/echo", headers={"Accept": "application/json"}) as response:
            seen = json.loads(await response.read())
        self.assertNotIn("user-agent", seen["headers"])

    async def test_large_upload_is_streamed(self):
        payload = b"z" * (3 * 1024 * 1024)
        async with self.client.post(self.base + "/echo", data=payload,
                                    headers=dict(BROWSER, Accept="application/json")) as response:
            seen = json.loads(await response.read())
        self.assertEqual(seen["size"], len(payload))

    async def test_chunked_upload_is_streamed(self):
        async def parts():
            for _ in range(20):
                yield b"y" * 1000

        async with self.client.post(self.base + "/echo", data=parts(),
                                    headers=dict(BROWSER, Accept="application/json")) as response:
            seen = json.loads(await response.read())
        self.assertEqual(seen["size"], 20000)

    async def test_websocket_relay(self):
        async with self.client.ws_connect(self.base + "/ws", protocols=("chat",)) as ws:
            self.assertEqual(ws.protocol, "chat")
            await ws.send_str("hi")
            self.assertEqual((await ws.receive()).data, "echo:hi")
            await ws.send_bytes(b"abc")
            self.assertEqual((await ws.receive()).data, b"cba")

    async def test_oversized_declared_body_is_refused(self):
        self.config.public.max_body_bytes = 10
        async with self.client.post(self.base + "/echo", data=b"x" * 100, headers=BROWSER) as response:
            self.assertEqual(response.status, 413)
            self.assert_anonymous(response, await response.read())


class ProxyDetection(ListenerCase):
    async def test_session_cookie_rules(self):
        response, _ = await self.get("/")
        cookie = response.headers["Set-Cookie"]
        name, _, rest = cookie.partition("=")
        self.assertEqual(name, self.persona.cookie_name)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertNotIn("Secure", cookie)
        value = rest.split(";")[0]
        again, _ = await self.get("/", headers=dict(BROWSER, Cookie=f"{name}={value}"))
        self.assertNotIn("Set-Cookie", again.headers)
        # Never on assets or on anything a shared cache may store.
        asset, _ = await self.get("/static/app.css")
        self.assertNotIn("Set-Cookie", asset.headers)
        cached, _ = await self.get("/cached")
        self.assertNotIn("Set-Cookie", cached.headers)

    async def test_canary_is_answered_by_the_trap_not_the_site(self):
        canary = self.engine.canaries.current().link_paths[0]
        before = len(self.hits)
        response, body = await self.get(canary)
        self.assertEqual(len(self.hits), before)
        self.assertIn(response.status, (200, 403))
        self.assertEqual(self.signals(), ["canary_path"])
        self.assertEqual(response.headers["Server"], self.persona.banner)
        self.assert_anonymous(response, body)

    async def test_canary_directory_listing_leads_deeper(self):
        segment = self.engine.canaries.current().segments["link"]
        response, body = await self.get(f"/{segment}/")
        self.assertEqual(response.status, 200)
        self.assertIn(b"Index of", body)
        self.assertIn(b"<a href=", body)

    async def test_hidden_instruction_endpoint(self):
        current = self.engine.canaries.current()
        token = self.engine.canaries.instruction_token("x")
        response, body = await self.get(f"{current.instruction_path}?ref={token}")
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(body)["status"], "registered")
        self.assertEqual(self.signals(), ["hidden_instruction"])

    async def test_bait_is_taken_over_only_when_the_site_has_nothing(self):
        response, body = await self.get("/.env")
        self.assertEqual(response.status, 200)
        self.assertIn(self.engine.honeytokens.value("db_password").encode(), body)
        self.assertIn("/.env", self.hits)            # the site was asked first
        self.assertIn("ETag", response.headers)
        self.assert_anonymous(response, body)

        real, body = await self.get("/wp-login.php")  # exists on this site
        self.assertEqual(real.status, 200)
        self.assertIn(b"Real content.", body)
        self.assertEqual(self.signals(), ["probe_path"])

    async def test_missing_page_passes_through_and_is_learned(self):
        response, body = await self.get("/nothing-here")
        self.assertEqual(response.status, 404)
        self.assertEqual(body, b'{"error":"no such thing"}')
        self.assertEqual(self.persona.learned_not_found.body, body)
        self.assertEqual(self.persona.server_header, "gunicorn")

    async def test_robots_is_merged(self):
        response, body = await self.get("/robots.txt", headers={"User-Agent": "x", "Accept": "*/*"})
        text = body.decode()
        self.assertEqual(response.status, 200)
        self.assertIn("Disallow: /private/", text)
        for entry in self.engine.canaries.current().disallow:
            self.assertIn(f"Disallow: {entry}", text)
        self.assertEqual(text.count("User-agent: *"), 1)
        self.assertEqual(int(response.headers["Content-Length"]), len(body))

    async def test_honeytoken_from_bait_is_detected_when_used(self):
        _, body = await self.get("/.env")
        secret = self.engine.honeytokens.value("api_key")
        self.assertIn(secret.encode(), body)
        await self.get("/api/data", headers=dict(BROWSER, Authorization=f"Bearer {secret}"))
        self.assertIn("honeytoken", self.signals())
        self.assertEqual(self.engine.stats()["tiers"]["high"], 1)

    async def test_attack_in_small_post_body_is_seen(self):
        async with self.client.post(
            self.base + "/echo", data=b"q=1'+or+'1'%3D'1",
            headers=dict(BROWSER, **{"Content-Type": "application/x-www-form-urlencoded"}),
        ) as response:
            seen = json.loads(await response.read())
        self.assertEqual(seen["size"], 16)          # body still reached the site intact
        self.assertEqual(self.signals(), ["attack_payload"])

    async def test_nothing_identifies_the_trap(self):
        current = self.engine.canaries.current()
        paths = ["/", "/.env", "/.git/config", "/backup.zip", "/nothing", "/robots.txt",
                 current.link_paths[0], current.robots_only_path, current.instruction_path,
                 f"/{current.segments['comment']}/x.sql", f"/{current.segments['link']}/y.json"]
        for path in paths:
            response, body = await self.get(path, headers={"User-Agent": "curl/8.5.0", "Accept": "*/*"})
            self.assert_anonymous(response, body)
            self.assertNotIn("X-Powered-By", response.headers)


class ProxyEdges(ListenerCase):
    def configure(self, config):
        config.inject.max_body_bytes = 20000
        config.whitelist = []

    async def test_page_over_the_cap_is_streamed_untouched(self):
        response, body = await self.get("/big")
        self.assertEqual(response.status, 200)
        self.assertGreater(len(body), 50000)
        self.assertNotIn(self.engine.canaries.current().instruction_path.encode(), body)
        self.assertTrue(body.startswith(b"<html><body><p>xxx"))
        self.assertTrue(body.endswith(b"</body></html>"))

    async def test_malformed_request_gets_a_plain_server_error(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.app.port)
        writer.write(b"\x16\x03\x01 not http at all\r\n\r\n")
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(), 5)
        writer.close()
        text = raw.decode("latin-1").lower()
        self.assertIn(" 400 bad request", text.splitlines()[0])
        self.assertIn(f"server: {self.persona.banner.lower()}", text)
        for word in ("aiohttp", "python", "tr4p"):
            self.assertNotIn(word, text)

    async def test_only_origin_form_targets_are_proxied(self):
        # Absolute-form targets must never be appended to the upstream
        # address: that would let a client pick the host the proxy talks to.
        for target in (b"http://other.example/", b"s.other.example://x", b"*"):
            before = len(self.hits)
            reader, writer = await asyncio.open_connection("127.0.0.1", self.app.port)
            writer.write(b"GET " + target + b" HTTP/1.1\r\nHost: shop.example\r\n"
                         b"Connection: close\r\n\r\n")
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(), 5)
            writer.close()
            self.assertIn(b" 400 ", raw.split(b"\r\n")[0], target)
            self.assertEqual(len(self.hits), before, target)

    async def test_upstream_down_gives_bad_gateway(self):
        await self.upstream_runner.cleanup()
        self.upstream_runner = None
        response, body = await self.get("/")
        self.assertEqual(response.status, 502)
        self.assertIn(b"502", body)
        self.assert_anonymous(response, body)


class ProxyBehindTrustedProxy(ListenerCase):
    def configure(self, config):
        config.public.trusted_proxies = ["127.0.0.1"]
        config.whitelist = ["198.51.100.0/24"]

    async def test_real_client_address_and_scheme_come_from_the_proxy(self):
        headers = dict(BROWSER, **{"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https"})
        response, _ = await self.get("/.env", headers=headers)
        self.assertEqual(self.sink.events[0]["ip"], "203.0.113.9")
        self.assertIn("; Secure", response.headers["Set-Cookie"])

    async def test_spoofed_entries_left_of_the_real_one_are_ignored(self):
        headers = dict(BROWSER, **{"X-Forwarded-For": "192.0.2.66, 203.0.113.9, 127.0.0.1"})
        await self.get("/.env", headers=headers)
        self.assertEqual(self.sink.events[0]["ip"], "203.0.113.9")

    async def test_whitelisted_client_sees_the_plain_site(self):
        headers = dict(BROWSER, **{"X-Forwarded-For": "198.51.100.20"})
        response, body = await self.get("/", headers=headers)
        self.assertEqual(body, HOME_PAGE)
        self.assertNotIn("Set-Cookie", response.headers)
        canary = self.engine.canaries.current().link_paths[0]
        await self.get(canary, headers=headers)
        self.assertEqual(self.sink.events, [])


class ProxyUntrustedPeer(ListenerCase):
    async def test_forwarded_headers_from_strangers_are_ignored(self):
        headers = dict(BROWSER, **{"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https"})
        response, _ = await self.get("/.env", headers=headers)
        self.assertEqual(self.sink.events[0]["ip"], "127.0.0.1")
        self.assertNotIn("Secure", response.headers["Set-Cookie"])


class InjectionDisabled(ListenerCase):
    def configure(self, config):
        config.inject.enabled = False

    async def test_pages_are_untouched_when_injection_is_off(self):
        response, body = await self.get("/")
        self.assertEqual(body, HOME_PAGE)
        self.assertEqual(response.headers["ETag"], '"abc123"')


class Standalone(ListenerCase):
    mode = "standalone"

    async def test_built_in_site_with_tripwires(self):
        response, body = await self.get("/")
        self.assertEqual(response.status, 200)
        self.assertIn(self.persona.site_name.encode(), body)
        self.assertIn(self.engine.canaries.current().instruction_path.encode(), body)
        self.assertIn(b"/assets/site.css", body)
        self.assertEqual(response.headers["Server"], self.persona.banner)
        self.assert_anonymous(response, body)

    async def test_assets_login_and_missing_pages(self):
        css, body = await self.get("/assets/site.css")
        self.assertEqual(css.status, 200)
        self.assertTrue(css.headers["Content-Type"].startswith("text/css"))
        self.assertNotIn("Set-Cookie", css.headers)
        async with self.client.post(self.base + "/login", data=b"username=a&password=b",
                                    headers=BROWSER) as response:
            self.assertIn(b"Invalid username or password.", await response.read())
        missing, body = await self.get("/nope")
        self.assertEqual(missing.status, 404)
        self.assert_anonymous(missing, body)

    async def test_robots_and_bait(self):
        _, body = await self.get("/robots.txt")
        self.assertTrue(body.startswith(b"User-agent: *\nDisallow: /"))
        response, body = await self.get("/.env")
        self.assertEqual(response.status, 200)
        self.assertIn(b"DB_PASSWORD=", body)
        php, _ = await self.get("/wp-login.php")
        self.assertEqual(php.status, 404)
        self.assertEqual(self.signals(), ["probe_path", "probe_path"])
