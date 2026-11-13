"""Alerts to a webhook and by e-mail.

Alert content includes text chosen by an attacker (paths, user agents), and a
webhook is an outbound request made by a security tool, so this module is
deliberately careful:

* Webhook targets must be http(s). Private, loopback and other non-public
  addresses are refused unless the defender explicitly allows them, and the
  check is made on the addresses actually connected to, not just the name.
* Redirects are not followed; every send has a timeout.
* Alerts are de-duplicated and rate limited, so a flood of detections cannot
  become a flood of messages. Suppressed alerts are counted and reported.
* Attacker-supplied text is stripped of control characters, shortened and
  defused before it goes anywhere. E-mail is plain text with a fixed subject.
* The SMTP password is never in the config file. It comes from the
  TR4P_SMTP_PASSWORD environment variable or from `smtp.secret` in the home
  directory.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import smtplib
import socket
import ssl
import time
from collections import deque
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver
from aiohttp.resolver import DefaultResolver

from tr4p.config import AlertConfig
from tr4p.fsutil import is_private

log = logging.getLogger("tr4p.alerts")

SMTP_PASSWORD_ENV = "TR4P_SMTP_PASSWORD"
SMTP_PASSWORD_FILE = "smtp.secret"
QUEUE_LIMIT = 100
TEXT_LIMIT = 200
SMTP_TIMEOUT = 10.0
_TIER_RANK = {"": 0, "none": 0, "low": 1, "medium": 2, "high": 3}
_DEFUSE = str.maketrans({"@": "(at)", "<": "(", ">": ")", "`": "'", "[": "(", "]": ")", "|": "/"})


class AlertError(Exception):
    """An alert target is not acceptable."""


def clean(value: object, limit: int = TEXT_LIMIT) -> str:
    """Make attacker-supplied text safe to show in chat tools and mail:
    no control characters, no mention/link/markup triggers, bounded length."""
    text = "".join(ch if ch.isprintable() else "?" for ch in str(value))
    return text[:limit].translate(_DEFUSE)


def is_public_address(address: str) -> bool:
    try:
        return ipaddress.ip_address(address.split("%")[0]).is_global
    except ValueError:
        return False


def check_webhook_url(url: str, allow_private: bool) -> None:
    """Reject anything but http(s), and literal non-public addresses."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise AlertError("webhook URL must be http(s) with a host")
    host = parts.hostname
    if allow_private:
        return
    if host.lower() in ("localhost",) or host.lower().endswith((".localhost", ".local", ".internal")):
        raise AlertError("webhook host is a local name")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return   # a name: checked again when it is resolved
    if not is_public_address(host):
        raise AlertError("webhook address is not public")


class GuardedResolver(AbstractResolver):
    """Resolver that refuses names pointing at non-public addresses. Used
    for the connection itself, so a name cannot pass the check and then
    resolve somewhere else."""

    def __init__(self, allow_private: bool, inner: AbstractResolver | None = None) -> None:
        self._allow_private = allow_private
        self._inner = inner or DefaultResolver()

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        results = await self._inner.resolve(host, port, family)
        if not self._allow_private:
            for item in results:
                if not is_public_address(item["host"]):
                    raise OSError(f"{host} resolves to a non-public address")
        return results

    async def close(self) -> None:
        await self._inner.close()


def smtp_password(home: Path | None) -> str:
    value = os.environ.get(SMTP_PASSWORD_ENV, "")
    if value or home is None:
        return value
    path = home / SMTP_PASSWORD_FILE
    if not path.is_file():
        return ""
    if not is_private(path):
        log.warning("%s is readable by other users; run chmod 600 on it", path)
    return path.read_text(encoding="utf-8").strip()


class AlertManager:
    def __init__(
        self,
        config: AlertConfig,
        home: Path | None = None,
        instance: str = "default",
        clock: Callable[[], float] = time.monotonic,
        resolver: AbstractResolver | None = None,
    ) -> None:
        self._config = config
        self._home = home
        self._instance = instance
        self._clock = clock
        self._resolver = resolver
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=QUEUE_LIMIT)
        self._recent: dict[tuple[str, str, str], float] = {}
        self._sent_times: deque[float] = deque()
        self._pending_suppressed = 0
        self._task: asyncio.Task[None] | None = None
        self.sent = 0
        self.failed = 0
        self.suppressed = 0

    # ---------------------------------------------------------------- intake

    def configured(self) -> bool:
        config = self._config
        return bool(config.webhook_url or (config.email_to and config.smtp_host))

    def stats(self) -> dict[str, Any]:
        return {"configured": self.configured(), "sent": self.sent,
                "failed": self.failed, "suppressed": self.suppressed}

    def submit(self, event: dict[str, Any]) -> bool:
        """Offer an event. Returns True if an alert was queued for it."""
        if not self.configured() or not event.get("alert"):
            return False
        if _TIER_RANK.get(str(event.get("tier", "")), 0) < _TIER_RANK[self._config.min_tier]:
            return False
        now = self._clock()
        key = (str(event.get("session", "")), str(event.get("signal") or event.get("kind", "")),
               str(event.get("tier", "")))
        window = self._config.dedupe_minutes * 60.0
        last = self._recent.get(key)
        if last is not None and now - last < window:
            return self._suppress()
        while self._sent_times and now - self._sent_times[0] >= 60.0:
            self._sent_times.popleft()
        if len(self._sent_times) >= self._config.rate_per_minute or self._queue.full():
            return self._suppress()
        if len(self._recent) > 4096:
            self._recent = {k: t for k, t in self._recent.items() if now - t < window}
        self._recent[key] = now
        self._sent_times.append(now)
        self._queue.put_nowait(self._payload(event))
        return True

    def _suppress(self) -> bool:
        self.suppressed += 1
        self._pending_suppressed += 1
        return False

    def _payload(self, event: dict[str, Any]) -> dict[str, Any]:
        safe = {
            "time": float(event.get("ts", 0.0)),
            "kind": clean(event.get("kind", "")),
            "tier": clean(event.get("tier", "")),
            "signal": clean(event.get("signal", "")),
            "detail": clean(event.get("detail", "")),
            "score": float(event.get("score", 0.0)),
            "address": clean(event.get("ip", "")),
            "method": clean(event.get("method", ""), 12),
            "path": clean(event.get("path", "")),
            "user_agent": clean(event.get("user_agent", "")),
            "session": clean(event.get("session", ""), 40),
        }
        what = safe["signal"] or safe["kind"]
        summary = (f"[{clean(self._instance, 40)}] {safe['tier']} tier: {what} "
                   f"from {safe['address']} (score {safe['score']:.0f}) {safe['detail']}")
        if self._pending_suppressed:
            summary += f" (+{self._pending_suppressed} similar alerts not sent)"
            self._pending_suppressed = 0
        return {"text": summary, "content": summary, "instance": clean(self._instance, 40),
                "event": safe}

    # --------------------------------------------------------------- delivery

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.ensure_future(self._run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    async def _run(self) -> None:
        while True:
            payload = await self._queue.get()
            await self.deliver(payload)

    async def deliver(self, payload: dict[str, Any]) -> None:
        config = self._config
        if config.webhook_url:
            await self._attempt(self._send_webhook(payload), "webhook")
        if config.email_to and config.smtp_host:
            await self._attempt(asyncio.to_thread(self._send_email, payload), "e-mail")

    async def _attempt(self, action, name: str) -> None:
        try:
            await action
            self.sent += 1
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.failed += 1
            log.warning("%s alert failed: %s", name, clean(exc))

    async def _send_webhook(self, payload: dict[str, Any]) -> None:
        config = self._config
        check_webhook_url(config.webhook_url, config.webhook_allow_private)
        resolver = self._resolver or GuardedResolver(config.webhook_allow_private)
        connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False, limit=2)
        timeout = aiohttp.ClientTimeout(total=config.webhook_timeout)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout,
                                         cookie_jar=aiohttp.DummyCookieJar()) as session:
            async with session.post(config.webhook_url, json=payload,
                                    allow_redirects=False) as response:
                await response.read()
                if response.status >= 300:
                    raise AlertError(f"webhook answered {response.status}")

    def _send_email(self, payload: dict[str, Any]) -> None:
        config = self._config
        event = payload["event"]
        message = EmailMessage()
        message["Subject"] = f"Security alert: {event['tier']} tier session"
        message["From"] = config.email_from or config.smtp_user or "alerts@localhost"
        message["To"] = ", ".join(config.email_to)
        lines = [payload["text"], ""] + [f"{name}: {value}" for name, value in event.items()]
        message.set_content("\n".join(lines))
        if config.smtp_security == "ssl":
            client: smtplib.SMTP = smtplib.SMTP_SSL(
                config.smtp_host, config.smtp_port, timeout=SMTP_TIMEOUT,
                context=ssl.create_default_context())
        else:
            client = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=SMTP_TIMEOUT)
        with client:
            if config.smtp_security == "starttls":
                client.starttls(context=ssl.create_default_context())
            if config.smtp_user:
                client.login(config.smtp_user, smtp_password(self._home))
            client.send_message(message)
