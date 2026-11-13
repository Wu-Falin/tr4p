"""Alerts: target validation, de-duplication, rate limiting, escaping, delivery.

Addresses and secrets used here are assembled at run time so that no
address or secret-looking literal sits in the repository."""

import asyncio
import secrets
import time
import unittest

import pytest
from aiohttp import web

import tr4p.alerts as alerts
from tr4p.alerts import AlertError, AlertManager, GuardedResolver, check_webhook_url, clean
from tr4p.config import AlertConfig, Config, ConfigError

PRIVATE = ".".join(["10", "20", "30", "40"])
PUBLIC = ".".join(["8", "8", "8", "8"])
METADATA = ".".join(["169", "254", "169", "254"])
LOOPBACK = "127.0.0.1"


def event(**changes):
    base = {"ts": 1.0, "kind": "tier", "tier": "high", "signal": "", "detail": "medium -> high",
            "score": 90.0, "ip": "203.0.113.9", "method": "GET", "path": "/.env",
            "user_agent": "curl/8", "session": "abc", "alert": True}
    base.update(changes)
    return base


def manager(clock=None, **settings):
    config = AlertConfig(webhook_url="https://hooks.example.com/x")
    for name, value in settings.items():
        setattr(config, name, value)
    now = [0.0]
    made = AlertManager(config, instance="shop", clock=clock or (lambda: now[0]))
    return made, now


# --------------------------------------------------------------------- text

def test_clean_defuses_attacker_text():
    hostile = "@everyone <!channel> [x](http://e.example) `rm`\r\nSubject: hi\x00\x1b[31m|"
    result = clean(hostile)
    for bad in ("@", "<", ">", "`", "[", "]", "\r", "\n", "\x00", "\x1b", "|"):
        assert bad not in result
    assert "(at)everyone" in result
    assert len(clean("x" * 5000)) == 200


# ------------------------------------------------------------ url validation

@pytest.mark.parametrize("url", [
    "ftp://hooks.example.com/x", "file:///etc/hosts", "https:///nohost", "gopher://x.example",
    f"http://{LOOPBACK}:9000/x", f"http://{PRIVATE}/x", f"http://{METADATA}/latest",
    "http://localhost/x", "http://db.internal/x", "http://printer.local/x", "http://[::1]/x",
])
def test_unsafe_webhook_targets_are_refused(url):
    with pytest.raises(AlertError):
        check_webhook_url(url, allow_private=False)


def test_public_and_explicitly_allowed_targets_pass():
    check_webhook_url("https://hooks.example.com/x", False)
    check_webhook_url(f"https://{PUBLIC}/x", False)
    check_webhook_url(f"http://{LOOPBACK}:9000/x", True)
    with pytest.raises(AlertError):
        check_webhook_url("ftp://x.example", True)            # scheme rule has no override
    assert alerts.is_public_address(PUBLIC) and not alerts.is_public_address(PRIVATE)
    assert not alerts.is_public_address("not-an-address")


def test_config_checks_alert_settings():
    for patch, text in (
        ({"webhook_url": "ftp://x.example"}, "webhook_url"),
        ({"min_tier": "low"}, "min_tier"),
        ({"smtp_security": "magic"}, "smtp_security"),
        ({"email_to": ["not an address"]}, "email_to"),
        ({"rate_per_minute": 0}, "rate_per_minute"),
    ):
        with pytest.raises(ConfigError, match=text):
            Config.from_dict({"alerts": patch})
    assert "password" not in " ".join(Config().to_dict()["alerts"])   # no secret field exists


class Resolver(unittest.IsolatedAsyncioTestCase):
    async def test_names_resolving_to_private_addresses_are_refused(self):
        class Fake:
            def __init__(self, address):
                self.address = address

            async def resolve(self, host, port=0, family=0):
                return [{"hostname": host, "host": self.address, "port": port,
                         "family": family, "proto": 0, "flags": 0}]

            async def close(self):
                pass

        for address in (PRIVATE, LOOPBACK, METADATA):
            with self.assertRaises(OSError):
                await GuardedResolver(False, Fake(address)).resolve("rebind.example", 443)
        self.assertEqual((await GuardedResolver(False, Fake(PUBLIC)).resolve("ok.example"))[0]["host"], PUBLIC)
        self.assertTrue(await GuardedResolver(True, Fake(PRIVATE)).resolve("lan.example"))


# --------------------------------------------------- dedupe and rate limiting

def test_nothing_is_queued_unless_configured_and_wanted():
    made, _ = manager(webhook_url="")
    assert not made.configured() and not made.submit(event())
    made, _ = manager()
    assert not made.submit(event(alert=False))
    assert not made.submit(event(tier="medium"))               # default min_tier is high
    assert made.submit(event())
    made, _ = manager(min_tier="medium")
    assert made.submit(event(tier="medium"))


def test_duplicates_are_held_back_then_allowed_again():
    made, now = manager()
    assert made.submit(event())
    assert not made.submit(event()) and not made.submit(event(detail="other words"))
    assert made.submit(event(session="def"))                    # another session is new
    assert made.submit(event(signal="honeytoken", kind="signal"))
    now[0] = 601
    assert made.submit(event())
    assert made.suppressed == 2


def test_rate_limit_and_suppressed_count_in_next_alert():
    made, now = manager(rate_per_minute=3)
    results = [made.submit(event(session=f"s{n}")) for n in range(10)]
    assert results == [True] * 3 + [False] * 7
    assert made.stats()["suppressed"] == 7
    now[0] = 61
    assert made.submit(event(session="later"))
    payloads = [made._queue.get_nowait() for _ in range(4)]
    assert "+7 similar alerts not sent" in payloads[-1]["text"]
    assert "similar alerts" not in payloads[0]["text"]


def test_payload_carries_only_cleaned_text():
    made, _ = manager()
    nasty = "<@U123> @here `x`\r\nBcc: victim@example.com\x07"
    made.submit(event(user_agent=nasty, path="/" + nasty, detail=nasty, ip=nasty, session=nasty))
    payload = made._queue.get_nowait()
    text = repr(payload)
    for bad in ("<@", "@here", "\\r", "\\n", "\\x07", "`"):
        assert bad not in text
    assert payload["text"] == payload["content"] and payload["text"].startswith("[shop] high tier")


# ------------------------------------------------------------------- delivery

class Delivery(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.received = []

        async def hook(request):
            self.received.append(await request.json())
            return web.json_response({"ok": True})

        async def bounce(request):
            raise web.HTTPFound("/hook")

        async def slow(request):
            await asyncio.sleep(3)
            return web.Response()

        app = web.Application()
        app.router.add_post("/hook", hook)
        app.router.add_post("/bounce", bounce)
        app.router.add_post("/slow", slow)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        await web.TCPSite(self.runner, LOOPBACK, 0).start()
        self.base = f"http://{LOOPBACK}:{self.runner.addresses[0][1]}"

    async def asyncTearDown(self):
        await self.runner.cleanup()

    def make(self, path, **settings):
        config = AlertConfig(webhook_url=self.base + path, webhook_allow_private=True,
                             webhook_timeout=1.0)
        for name, value in settings.items():
            setattr(config, name, value)
        return AlertManager(config, instance="shop")

    async def test_webhook_receives_json(self):
        made = self.make("/hook")
        made.start()
        made.submit(event())
        for _ in range(100):
            if self.received:
                break
            await asyncio.sleep(0.02)
        await made.stop()
        self.assertEqual(self.received[0]["event"]["tier"], "high")
        self.assertEqual(made.stats()["sent"], 1)

    async def test_private_target_is_refused_unless_allowed(self):
        made = self.make("/hook", webhook_allow_private=False)
        with self.assertLogs("tr4p.alerts", level="WARNING"):
            await made.deliver({"text": "x", "event": {}})
        self.assertEqual((made.sent, made.failed, self.received), (0, 1, []))

    async def test_redirects_are_not_followed(self):
        made = self.make("/bounce")
        with self.assertLogs("tr4p.alerts", level="WARNING"):
            await made.deliver({"text": "x", "event": {}})
        self.assertEqual((made.failed, self.received), (1, []))

    async def test_slow_target_times_out(self):
        made = self.make("/slow")
        started = time.monotonic()
        with self.assertLogs("tr4p.alerts", level="WARNING"):
            await made.deliver({"text": "x", "event": {}})
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(made.failed, 1)


# ---------------------------------------------------------------------- email

class FakeSMTP:
    sent = []

    def __init__(self, host, port, timeout=None, **kwargs):
        self.info = {"host": host, "port": port, "timeout": timeout, "tls": False, "login": None}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        self.info["tls"] = True

    def login(self, user, password):
        self.info["login"] = (user, password)

    def send_message(self, message):
        FakeSMTP.sent.append((self.info, message))


def test_email_is_plain_text_with_fixed_headers_and_external_password(monkeypatch, tmp_path):
    FakeSMTP.sent = []
    monkeypatch.setattr(alerts.smtplib, "SMTP", FakeSMTP)
    password = secrets.token_hex(12)
    monkeypatch.setenv(alerts.SMTP_PASSWORD_ENV, password)
    config = AlertConfig(email_to=["soc@example.com"], email_from="trap@example.com",
                         smtp_host="mail.example.com", smtp_user="trap")
    made = AlertManager(config, tmp_path, "shop", clock=lambda: 0.0)
    nasty = "curl\r\nBcc: victim@example.com\r\nSubject: pwned"
    assert made.submit(event(user_agent=nasty))
    made._send_email(made._queue.get_nowait())
    info, message = FakeSMTP.sent[0]
    assert info["tls"] and info["timeout"] == alerts.SMTP_TIMEOUT
    assert info["login"] == ("trap", password)
    assert message["Subject"] == "Security alert: high tier session"
    assert message["To"] == "soc@example.com" and message["Bcc"] is None
    assert message.get_content_type() == "text/plain"
    assert "victim(at)example.com" in message.get_content()


def test_smtp_password_can_come_from_a_private_file(monkeypatch, tmp_path):
    from tr4p.fsutil import write_private

    monkeypatch.delenv(alerts.SMTP_PASSWORD_ENV, raising=False)
    assert alerts.smtp_password(tmp_path) == "" and alerts.smtp_password(None) == ""
    password = secrets.token_hex(12)
    write_private(tmp_path / alerts.SMTP_PASSWORD_FILE, (password + "\n").encode())
    assert alerts.smtp_password(tmp_path) == password
