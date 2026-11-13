"""Detection engine.

Turns requests into signals, signals into a confidence score, and the score
into a tier. For trapped sessions it also decides how long the answer is held
back. It knows nothing about HTTP libraries or storage: the listener feeds it
plain request facts, and everything it learns leaves through a sink. That
keeps the rules easy to read and easy to test.

Session cookie and hash chain
-----------------------------
The session cookie is the head of an HMAC hash chain:

    link(0) = HMAC(key, id)
    link(n) = HMAC(key, link(n-1) | id | n)
    cookie  = id | n | first bytes of link(n)

`n` is the tarpit phase. Only the server can produce the next link, so a
client can neither invent a phase nor alter one. Server memory stays the
authority against replaying an older cookie; what the chain adds is that a
restarted server resumes a trapped session at the phase its cookie proves.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import random
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import parse_qsl, unquote_plus

from tr4p import scoring
from tr4p.blocklist import Blocklist
from tr4p.canary import (
    KIND_INSTRUCTION,
    KIND_ROBOTS,
    Canaries,
    CanaryHit,
    bait_class,
)
from tr4p.clients import browser_header_anomaly, classify_agent, fingerprint
from tr4p.config import Config
from tr4p.honeytoken import Honeytokens
from tr4p.payloads import find_header_payload, find_payload
from tr4p.seed import Seed
from tr4p.session import GROUP_PREFIX, Session, SessionTable
from tr4p.whitelist import Whitelist

_AUTH_PATH = re.compile(
    r"(?:^|/)(?:login|log-in|signin|sign-in|auth|authenticate|sessions?|token"
    r"|wp-login\.php|xmlrpc\.php)(?:/|\.|$)",
    re.IGNORECASE,
)
_PAYLOAD_HEADERS = ("user-agent", "referer", "x-api-version", "x-forwarded-host")
_COOKIE_ID_BYTES = 12
_COOKIE_TAG_BYTES = 10
_COOKIE_LENGTH = 31  # base64url of id + phase byte + tag, padding stripped
MAX_PHASE = 40

# Signals describing what a client *is*; raised at most once per session.
_ONE_SHOT = frozenset({"scanner_ua", "generic_client", "header_anomaly", "no_assets"})
_HIDDEN_TYPES = frozenset({"canary_path", "robots_violation", "hidden_instruction"})

# After this many events for one signal type in one session, only every
# Nth is written. A scanner sending 50,000 probes must not fill the disk.
LOG_FULL_UNTIL = 20
LOG_EVERY = 25

PATH_LOG_LIMIT = 300
AGENT_LOG_LIMIT = 200


@dataclass(slots=True)
class RequestInfo:
    """The facts about one request that detection needs."""

    ip: str
    method: str
    path: str                      # decoded path
    target: str                    # raw path and query as sent
    query: str                     # raw query string
    headers: Mapping[str, str]     # case-insensitive, in arrival order
    http_version: tuple[int, int] = (1, 1)
    cookie: str | None = None      # value of our session cookie, if sent
    body: bytes | None = None      # small request bodies only
    is_asset: bool = False


@dataclass(slots=True)
class Signal:
    type: str
    detail: str


@dataclass(slots=True)
class Verdict:
    """What the engine concluded before the request is answered."""

    session: Session | None = None
    whitelisted: bool = False
    new_cookie: str | None = None
    canary: CanaryHit | None = None
    bait: str | None = None
    tier: str = scoring.TIER_NONE
    delay: float = 0.0      # seconds to hold the answer back (0 = not trapped)
    blocked: bool = False   # on the enforced blocklist: refuse
    teleport: bool = False  # redirect this request into the maze


class Sink(Protocol):
    def event(self, event: dict[str, Any]) -> None: ...

    def session(self, snapshot: dict[str, Any]) -> None: ...


@dataclass
class Counters:
    requests: int = 0
    whitelisted: int = 0
    signals: int = 0
    canary_hits: int = 0
    alerts: int = 0
    delayed: int = 0
    expired: int = 0
    blocked: int = 0
    teleported: int = 0
    decoy_touches: int = 0
    by_type: dict[str, int] = field(default_factory=dict)


class Engine:
    def __init__(
        self,
        config: Config,
        seed: Seed,
        sink: Sink,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._config = config
        self._det = config.detection
        self._seed = seed
        self._sink = sink
        self._clock = clock
        self._random = random.Random()
        self.canaries = Canaries(
            seed, config.canary.rotation_hours, config.canary.keep_rotations, clock
        )
        self.honeytokens = Honeytokens(seed)
        self.whitelist = Whitelist(config.whitelist)
        self.blocklist = Blocklist(config.block, clock)
        self.sessions = SessionTable(
            config.session.max_tracked,
            config.session.idle_seconds,
            config.session.flagged_days * 86400.0,
        )
        self.counters = Counters()
        # Set by the application to verify sessions that claim to be a
        # search engine crawler. Called with the session.
        self.crawler_hook: Callable[[Session], None] | None = None
        # Called with each session that is released (to wipe its decoy state).
        self.release_hook: Callable[[Session], None] | None = None

    # ------------------------------------------------------------------ cookies

    def _link(self, ident: bytes, phase: int, session: Session | None = None) -> bytes:
        """Chain link for a phase. Continues from the session's cached link
        when possible, otherwise walks the chain from its start."""
        if session is not None and session.chain is not None and session.chain_phase <= phase:
            link, at = session.chain, session.chain_phase
        else:
            link, at = self._seed.digest("chain", ident), 0
        for step in range(at + 1, phase + 1):
            link = self._seed.digest("chain", link, ident, step)
        if session is not None:
            session.chain, session.chain_phase = link, phase
        return link

    def mint_cookie(
        self, ident: bytes | None = None, phase: int = 0, session: Session | None = None
    ) -> str:
        """Create the signed, opaque session cookie value for a phase."""
        if ident is None:
            ident = secrets.token_bytes(_COOKIE_ID_BYTES)
        phase = max(0, min(phase, MAX_PHASE))
        tag = self._link(ident, phase, session)[:_COOKIE_TAG_BYTES]
        raw = ident + bytes([phase]) + tag
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    @staticmethod
    def _parse_cookie(value: str | None) -> tuple[bytes, int, bytes] | None:
        if not value or len(value) != _COOKIE_LENGTH:
            return None
        try:
            raw = base64.urlsafe_b64decode(value + "=")
        except (binascii.Error, ValueError):
            return None
        if len(raw) != _COOKIE_ID_BYTES + 1 + _COOKIE_TAG_BYTES:
            return None
        phase = raw[_COOKIE_ID_BYTES]
        if phase > MAX_PHASE:
            return None
        return raw[:_COOKIE_ID_BYTES], phase, raw[_COOKIE_ID_BYTES + 1:]

    def read_cookie(self, value: str | None) -> tuple[str, int] | None:
        """Return (session id, phase) carried by a cookie, or None if it is
        not one of ours."""
        parsed = self._parse_cookie(value)
        if parsed is None:
            return None
        ident, phase, tag = parsed
        expected = self._link(ident, phase)[:_COOKIE_TAG_BYTES]
        if not secrets.compare_digest(expected, tag):
            return None
        return ident.hex(), phase

    # ----------------------------------------------------------------- requests

    def begin(self, info: RequestInfo) -> Verdict:
        """Inspect a request before it is answered."""
        now = self._clock()
        self.counters.requests += 1
        if self.whitelist.contains(info.ip):
            self.counters.whitelisted += 1
            return Verdict(whitelisted=True)

        client_print = fingerprint(info.headers, info.http_version)
        group_key = GROUP_PREFIX + hashlib.sha256(
            f"{info.ip}|{client_print}".encode("utf-8", "replace")
        ).hexdigest()[:20]

        entry = self.blocklist.hit(group_key)
        if entry is not None:
            self.counters.blocked += 1
            if entry.hits == 1 or entry.hits % 100 == 0:
                self._sink.event({
                    "ts": now, "kind": "blocked", "session": group_key, "ip": info.ip,
                    "method": info.method, "path": info.target[:PATH_LOG_LIMIT], "signal": "",
                    "detail": f"refused, on the blocklist (x{entry.hits})", "score": 0.0,
                    "tier": "high", "user_agent": info.headers.get("user-agent", "")[:AGENT_LOG_LIMIT],
                    "alert": False,
                })
            return Verdict(blocked=True)

        ident: bytes | None = None
        token_phase = 0
        session: Session | None = None
        parsed = self._parse_cookie(info.cookie)
        if parsed is not None:
            candidate, token_phase, tag = parsed
            known = self.sessions.get(candidate.hex())
            expected = self._link(candidate, token_phase, known)[:_COOKIE_TAG_BYTES]
            if secrets.compare_digest(expected, tag):
                ident, session = candidate, known
                if session is None:
                    session = self.sessions.create(ident.hex(), now)
                    self._adopt_group(session, group_key, now)
        if session is None:
            session = self.sessions.get(group_key) or self.sessions.create(group_key, now)
        self._expire(session, now)

        user_agent = info.headers.get("user-agent", "")
        if user_agent != session.user_agent:
            session.agent_class = ""
        session.last_seen = now
        session.ip = info.ip
        session.fingerprint = client_print
        session.user_agent = user_agent
        session.group_key = group_key
        session.requests += 1

        verdict = Verdict(session=session)
        signals = self._inspect(info, session, verdict, now)
        self._apply(session, signals, info, now)
        verdict.tier = session.tier

        if self._is_trapped(session):
            if token_phase > session.phase:
                # The cookie proves a later phase than we remember (restart).
                session.phase = token_phase
            self._plan_delay(session, info, verdict, now)
            self._plan_teleport(session, info, verdict)

        if ident is None:
            mode = self._config.session.cookie_mode
            if mode == "always" or (mode == "on_signal" and session.flagged):
                verdict.new_cookie = self.mint_cookie()
        elif token_phase != session.phase:
            # Keep the cookie at the head of the chain (or back at its start
            # once a trap has expired or been released).
            verdict.new_cookie = self.mint_cookie(ident, session.phase, session)
        return verdict

    def finish(
        self, info: RequestInfo, verdict: Verdict, status: int, content_type: str
    ) -> None:
        """Account for the backend's answer. `status` is what the real site
        or built-in site said, before any bait takeover."""
        session = verdict.session
        if session is None:
            return
        now = self._clock()
        det = self._det
        signals: list[Signal] = []

        if verdict.bait == "if_missing" and status == 404:
            signals.append(Signal("probe_path", "scanner target that does not exist here"))

        if info.is_asset:
            session.assets += 1
        elif status == 404:
            if now - session.not_found_start > det.not_found_window:
                session.not_found_start = now
                session.not_found_count = 0
            session.not_found_count += 1
            if session.not_found_count == det.not_found_max + 1:
                signals.append(Signal(
                    "not_found_burst",
                    f"more than {det.not_found_max} missing pages in "
                    f"{det.not_found_window:g}s",
                ))
        elif (
            status == 200
            and info.method == "GET"
            and verdict.canary is None
            and content_type.startswith("text/html")
        ):
            session.pages += 1
            if (
                session.pages >= det.no_assets_min_pages
                and session.assets == 0
                and "no_assets" not in session.signals
            ):
                signals.append(Signal(
                    "no_assets",
                    f"{session.pages} pages fetched without any style, script or image",
                ))

        if signals:
            self._apply(session, signals, info, now)
            verdict.tier = session.tier

    # ------------------------------------------------------------------ signals

    def _inspect(
        self, info: RequestInfo, session: Session, verdict: Verdict, now: float
    ) -> list[Signal]:
        det = self._det
        signals: list[Signal] = []
        headers = info.headers

        token = self._find_honeytoken(info)
        if token is not None:
            signals.append(Signal("honeytoken", f"planted secret used: {token}"))

        hit = self.canaries.match(info.path)
        if hit is not None:
            verdict.canary = hit
            signals.append(self._canary_signal(hit, info))
        else:
            verdict.bait = bait_class(info.path)
            if verdict.bait == "always":
                signals.append(Signal("probe_path", "request for a secrets or backup file"))

        payload = find_payload(info.target)
        if payload is None and info.body:
            payload = find_payload(info.body.decode("utf-8", "replace"))
        if payload is None:
            for name in _PAYLOAD_HEADERS:
                value = headers.get(name)
                if value and find_header_payload(value):
                    payload = f"header:{name}"
                    break
        if payload is not None:
            signals.append(Signal("attack_payload", f"{payload} pattern in request"))

        if not session.agent_class:
            category, name = classify_agent(session.user_agent, det.extra_scanner_agents)
            session.agent_class, session.agent_name = category, name
            if category == "scanner":
                signals.append(Signal("scanner_ua", f"scanner user agent: {name}"))
            elif category == "generic":
                signals.append(Signal("generic_client", f"automation client: {name}"))
        if (
            session.agent_class == "browser"
            and not info.is_asset
            and "header_anomaly" not in session.signals
        ):
            reason = browser_header_anomaly(headers, info.http_version)
            if reason:
                signals.append(Signal("header_anomaly", reason))

        if not info.is_asset:
            if now - session.rate_start > det.rate_window:
                session.rate_start = now
                session.rate_count = 0
            session.rate_count += 1
            if session.rate_count == det.rate_max_requests + 1:
                signals.append(Signal(
                    "rate",
                    f"more than {det.rate_max_requests} requests in {det.rate_window:g}s",
                ))

        if info.method == "POST" and _AUTH_PATH.search(info.path):
            if now - session.auth_start > det.auth_window:
                session.auth_start = now
                session.auth_count = 0
            session.auth_count += 1
            if session.auth_count == det.auth_max + 1:
                signals.append(Signal(
                    "auth_burst",
                    f"more than {det.auth_max} login attempts in {det.auth_window:g}s",
                ))
        return signals

    def _canary_signal(self, hit: CanaryHit, info: RequestInfo) -> Signal:
        age = self.canaries.rotation() - hit.rotation
        suffix = "" if age == 0 else f" (rotated out {age} rotation(s) ago)"
        if hit.kind == KIND_INSTRUCTION:
            for _, value in parse_qsl(info.query, keep_blank_values=False):
                if self.canaries.check_instruction_token(value):
                    return Signal(
                        "hidden_instruction",
                        "followed hidden text addressed to automated agents" + suffix,
                    )
            return Signal("canary_path", "hidden agent path without its token" + suffix)
        if hit.kind == KIND_ROBOTS:
            return Signal("robots_violation", "path listed only in robots.txt" + suffix)
        return Signal("canary_path", f"hidden {hit.kind} canary" + suffix)

    def _find_honeytoken(self, info: RequestInfo) -> str | None:
        haystacks: list[str] = []
        if info.query:
            haystacks.append(unquote_plus(info.query))
        authorization = info.headers.get("authorization", "")
        if authorization:
            haystacks.append(authorization)
            scheme, _, value = authorization.partition(" ")
            if scheme.lower() == "basic":
                try:
                    haystacks.append(base64.b64decode(value + "==").decode("utf-8", "replace"))
                except (binascii.Error, ValueError):
                    pass
        for name in ("x-api-key", "x-auth-token", "cookie"):
            value = info.headers.get(name, "")
            if value:
                haystacks.append(value)
        if info.body:
            text = info.body.decode("utf-8", "replace")
            haystacks.append(text)
            if "%" in text or "+" in text:
                haystacks.append(unquote_plus(text))
        if not haystacks:
            return None
        found = self.honeytokens.find(*haystacks)
        return found.name if found else None

    # ------------------------------------------------------------------ scoring

    def _apply(
        self, session: Session, signals: list[Signal], info: RequestInfo | None, now: float
    ) -> None:
        if not signals:
            return
        was_flagged = session.flagged
        previous_tier = session.tier
        fresh: list[Signal] = []
        for signal in signals:
            count = session.signals.get(signal.type, 0)
            if count and signal.type in _ONE_SHOT:
                continue
            session.signals[signal.type] = count + 1
            session.last_signal = now
            fresh.append(signal)
            self.counters.signals += 1
            self.counters.by_type[signal.type] = self.counters.by_type.get(signal.type, 0) + 1
            if signal.type in _HIDDEN_TYPES or signal.type == "probe_path":
                self.counters.canary_hits += 1
        if not fresh:
            return
        self.sessions.promote(session)
        if not was_flagged:
            self._maybe_verify_crawler(session)
        self._rescore(session)

        for signal in fresh:
            count = session.signals[signal.type]
            if count <= LOG_FULL_UNTIL or count % LOG_EVERY == 0:
                detail = signal.detail if count <= LOG_FULL_UNTIL else f"{signal.detail} (x{count})"
                self._emit("signal", session, info, now, signal=signal.type, detail=detail,
                           alert=signal.type == "honeytoken")

        if scoring.TIER_RANK[session.tier] > scoring.TIER_RANK[previous_tier]:
            alert = session.tier in (scoring.TIER_MEDIUM, scoring.TIER_HIGH)
            if alert:
                self.counters.alerts += 1
            self._emit(
                "tier", session, info, now,
                detail=f"{previous_tier} -> {session.tier}", alert=alert,
            )
            if alert:
                self._link_group(session, now)
        self._list_if_high(session)
        self._sink.session(session.snapshot())

    def _rescore(self, session: Session, allow_drop: bool = False) -> None:
        det = self._det
        session.score = scoring.confidence(
            session.signals, det.weights, session.inherited, det.inherited_weight
        )
        if session.released or session.crawler == "verified":
            session.tier = scoring.TIER_NONE
            return
        tier = scoring.tier_for(
            session.signals, session.score,
            det.medium_threshold, det.trap_threshold, det.high_min_groups,
            session.inherited,
        )
        # Tiers only go up by themselves. They come down when a human
        # releases the session or when the evidence expires, never because
        # a new request happened to look harmless.
        if allow_drop or scoring.TIER_RANK[tier] > scoring.TIER_RANK[session.tier]:
            session.tier = tier

    def _list_if_high(self, session: Session) -> None:
        """High tier only, and never while a crawler check is still open."""
        if (
            session.tier == scoring.TIER_HIGH
            and not session.released
            and session.crawler in ("", "unverified")
        ):
            self.blocklist.add(session.group_key or session.key, session.ip, session.fingerprint)

    def _plan_teleport(self, session: Session, info: RequestInfo, verdict: Verdict) -> None:
        maze = self._config.maze
        if (
            session.tier == scoring.TIER_HIGH
            and maze.redirect_chance > 0
            and session.phase >= maze.redirect_min_phase
            and info.method == "GET"
            and not info.is_asset
            and verdict.canary is None
            and verdict.bait is None
            and self._random.random() < maze.redirect_chance
        ):
            verdict.teleport = True
            self.counters.teleported += 1

    def _is_trapped(self, session: Session) -> bool:
        return (
            session.tier in (scoring.TIER_MEDIUM, scoring.TIER_HIGH)
            and not session.released
            and session.crawler != "verified"
        )

    def _carry(self, source: Session, target: Session, now: float) -> None:
        """Copy evidence to a session that shares only address and header
        fingerprint with the source. It lands as inherited evidence."""
        for bucket in (source.signals, source.inherited):
            for name, count in bucket.items():
                if count > target.inherited.get(name, 0):
                    target.inherited[name] = count
        target.inherited_at = now
        target.phase = max(target.phase, source.phase)
        self.sessions.promote(target)
        self._rescore(target)

    def _adopt_group(self, session: Session, group_key: str, now: float) -> None:
        """A new cookie does not launder a trapped client: a fresh session
        inherits the evidence of the trapped cookie-less group it comes
        from, at reduced weight."""
        group = self.sessions.get(group_key)
        if group is None or group.released or not self._is_trapped(group):
            return
        self._expire(group, now)
        if self._is_trapped(group):
            self._carry(group, session, now)

    def _link_group(self, session: Session, now: float) -> None:
        """Carry a trapped cookie session's evidence over to its cookie-less
        group, so dropping the cookie does not reset detection."""
        if session.is_group or not session.group_key:
            return
        group = self.sessions.get(session.group_key)
        if group is None:
            group = self.sessions.create(session.group_key, now)
            group.ip, group.fingerprint = session.ip, session.fingerprint
            group.user_agent = session.user_agent
        if group.released:
            return
        group.last_seen = now
        self._carry(session, group, now)
        self._sink.session(group.snapshot())

    def _expire(self, session: Session, now: float) -> None:
        """Forget stale evidence. Inherited evidence goes first; a session's
        own signals follow once none has been added for the trap lifetime."""
        cfg = self._config.session
        changed = False
        if session.inherited and now - session.inherited_at > cfg.inherited_ttl_minutes * 60.0:
            session.inherited = {}
            changed = True
        if session.signals and now - session.last_signal > cfg.trap_ttl_hours * 3600.0:
            session.signals = {}
            session.pages = session.assets = 0
            session.agent_class = ""
            changed = True
        if not changed:
            return
        previous = session.tier
        self._rescore(session, allow_drop=True)
        if not self._is_trapped(session):
            session.phase = session.hits = 0
        if session.tier != previous:
            self.counters.expired += 1
            self._emit("expired", session, None, now,
                       detail=f"evidence expired: {previous} -> {session.tier}")
        self._sink.session(session.snapshot())

    # ------------------------------------------------------------------- tarpit

    def _plan_delay(
        self, session: Session, info: RequestInfo, verdict: Verdict, now: float
    ) -> None:
        """Decide how long this answer is held back, then count the request
        towards the next phase."""
        cfg = self._config.tarpit
        if not cfg.enabled or session.crawler == "pending":
            return
        light = session.tier == scoring.TIER_MEDIUM
        if light and info.is_asset:
            return   # the light tarpit spares a page's styles, scripts and images
        delay = min(cfg.max_delay, cfg.base_delay * (2 ** min(session.phase, 30)))
        if light:
            delay = min(delay, cfg.light_max_delay)
        if cfg.jitter:
            delay *= 1.0 + self._random.uniform(-cfg.jitter, cfg.jitter)
        verdict.delay = delay
        self.counters.delayed += 1
        session.hits += 1
        if session.hits % cfg.phase_requests == 0:
            self._advance(session, info, now, "")

    def _advance(self, session: Session, info: RequestInfo | None, now: float, reason: str) -> None:
        if session.phase >= MAX_PHASE:
            return
        cfg = self._config.tarpit
        still_growing = cfg.base_delay * (2 ** session.phase) < cfg.max_delay
        session.phase += 1
        # Routine steps are only worth a log line while the delay still grows.
        if reason or still_growing:
            detail = f"phase {session.phase}" + (f" ({reason})" if reason else "")
            self._emit("tarpit", session, info, now, detail=detail)

    def bump(self, key: str, reason: str) -> bool:
        """Adaptive difficulty: push a trapped session one phase further
        because of how it behaves while being held. Never applies to a
        session that is not already trapped."""
        session = self.sessions.get(key)
        if (
            session is None
            or not self._config.tarpit.adaptive
            or not self._is_trapped(session)
            or session.phase >= MAX_PHASE
        ):
            return False
        self._advance(session, None, self._clock(), reason)
        return True

    # ----------------------------------------------------------------- crawlers

    def _maybe_verify_crawler(self, session: Session) -> None:
        if (
            self._det.verify_crawlers
            and self.crawler_hook is not None
            and session.agent_class == "declared_bot"
            and not session.crawler
        ):
            session.crawler = "pending"
            self.crawler_hook(session)

    def crawler_result(self, key: str, verified: bool) -> None:
        """Record the outcome of a search engine crawler verification."""
        session = self.sessions.get(key)
        if session is None:
            return
        now = self._clock()
        session.crawler = "verified" if verified else "unverified"
        if verified:
            session.tier = scoring.TIER_NONE
            self.blocklist.remove(session.group_key or session.key)
            self._emit("system", session, None, now,
                       detail="verified search engine crawler, exempt from tiers")
        self._rescore(session)
        self._list_if_high(session)
        self._sink.session(session.snapshot())

    # ------------------------------------------------------------------ control

    def release(self, key: str, released: bool = True) -> bool:
        """Release (or re-arm) a session from the dashboard. Its linked
        cookie-less group follows, so the client is not re-trapped at once."""
        session = self.sessions.get(key)
        if session is None:
            return False
        now = self._clock()
        targets = [session]
        if not session.is_group and session.group_key:
            group = self.sessions.get(session.group_key)
            if group is not None:
                targets.append(group)
        for target in targets:
            target.released = released
            if released:
                target.tier = scoring.TIER_NONE
                target.phase = target.hits = 0
                self.blocklist.remove(target.group_key or target.key)
                if self.release_hook is not None:
                    self.release_hook(target)
            self.sessions.promote(target)
            self._rescore(target)
            self._list_if_high(target)       # back on the list when re-armed
            self._sink.session(target.snapshot())
        self._emit(
            "release", session, None, now,
            detail="released by operator" if released else "re-armed by operator",
        )
        return True

    def in_decoy(self, session: Session | None) -> bool:
        """High tier means the decoy, once any crawler check has finished."""
        return (
            session is not None
            and session.tier == scoring.TIER_HIGH
            and not session.released
            and session.crawler in ("", "unverified")
        )

    def decoy_touch(self, session: Session, info: RequestInfo, label: str) -> None:
        """Something marked sensitive inside the decoy was reached."""
        self.counters.decoy_touches += 1
        self._emit("decoy", session, info, self._clock(), signal="decoy_touch",
                   detail=f"sensitive decoy content reached: {label[:80]}", alert=True)

    def system_event(self, detail: str) -> None:
        """Record something the operator did (shown in the event feed)."""
        self._sink.event({
            "ts": self._clock(), "kind": "system", "session": "", "ip": "", "method": "",
            "path": "", "signal": "", "detail": detail, "score": 0.0, "tier": "",
            "user_agent": "", "alert": False,
        })

    def restore(self, snapshots: list[dict[str, Any]]) -> int:
        """Load flagged sessions saved by a previous run."""
        loaded = 0
        for data in snapshots:
            try:
                self.sessions.add(Session.restore(data))
                loaded += 1
            except (KeyError, TypeError, ValueError):
                continue
        return loaded

    def sweep(self) -> int:
        return self.sessions.sweep(self._clock())

    def stats(self) -> dict[str, Any]:
        counters = self.counters
        return {
            "requests": counters.requests,
            "whitelisted": counters.whitelisted,
            "signals": counters.signals,
            "canary_hits": counters.canary_hits,
            "alerts": counters.alerts,
            "delayed": counters.delayed,
            "expired": counters.expired,
            "blocked": counters.blocked,
            "teleported": counters.teleported,
            "decoy_touches": counters.decoy_touches,
            "blocklist": len(self.blocklist),
            "by_type": dict(counters.by_type),
            "tracked_sessions": len(self.sessions),
            "tiers": self.sessions.tier_counts(),
        }

    # ------------------------------------------------------------------- events

    def _emit(
        self,
        kind: str,
        session: Session,
        info: RequestInfo | None,
        now: float,
        signal: str = "",
        detail: str = "",
        alert: bool = False,
    ) -> None:
        self._sink.event({
            "ts": now,
            "kind": kind,
            "session": session.key,
            "ip": session.ip,
            "method": info.method if info else "",
            "path": info.target[:PATH_LOG_LIMIT] if info else "",
            "signal": signal,
            "detail": detail,
            "score": session.score,
            "tier": session.tier,
            "user_agent": session.user_agent[:AGENT_LOG_LIMIT],
            "alert": alert,
        })
