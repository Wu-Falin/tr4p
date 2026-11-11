"""Dashboard authentication building blocks.

Passwords are stored as salted scrypt hashes. Sessions are random tokens held
in memory, so restarting the service signs everyone out. Failed logins are
rate limited per address and globally.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 256

_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_PBKDF2_ROUNDS = 600_000
_KEY_BYTES = 32


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def password_problem(password: str) -> str | None:
    """Explain why a password is not acceptable, or return None."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
    if len(set(password)) < 4:
        return "Password is too repetitive."
    return None


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    raw = password.encode("utf-8")
    try:
        key = hashlib.scrypt(raw, salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_KEY_BYTES)
        return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(key)}"
    except (AttributeError, ValueError):
        # Python builds without scrypt support fall back to PBKDF2.
        key = hashlib.pbkdf2_hmac("sha256", raw, salt, _PBKDF2_ROUNDS, _KEY_BYTES)
        return f"pbkdf2${_PBKDF2_ROUNDS}${_b64(salt)}${_b64(key)}"


def verify_password(password: str, stored: str) -> bool:
    raw = password.encode("utf-8")
    try:
        parts = stored.split("$")
        if parts[0] == "scrypt" and len(parts) == 6:
            salt, expected = base64.b64decode(parts[4]), base64.b64decode(parts[5])
            key = hashlib.scrypt(raw, salt=salt, n=int(parts[1]), r=int(parts[2]),
                                 p=int(parts[3]), dklen=len(expected))
        elif parts[0] == "pbkdf2" and len(parts) == 4:
            salt, expected = base64.b64decode(parts[2]), base64.b64decode(parts[3])
            key = hashlib.pbkdf2_hmac("sha256", raw, salt, int(parts[1]), len(expected))
        else:
            return False
    except (ValueError, AttributeError, IndexError):
        return False
    return hmac.compare_digest(key, expected)


class LoginLimiter:
    """Locks an address out after repeated failures, and slows everyone down
    when failures arrive from many addresses at once."""

    def __init__(
        self,
        max_failures: int = 5,
        window: float = 300.0,
        global_max: int = 40,
        max_tracked: int = 4096,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max = max_failures
        self._window = window
        self._global_max = global_max
        self._max_tracked = max_tracked
        self._clock = clock
        self._failures: OrderedDict[str, list[float]] = OrderedDict()
        self._all: list[float] = []

    def retry_after(self, address: str) -> float:
        """Seconds the caller must wait before trying again (0 if allowed)."""
        now = self._clock()
        self._all = [stamp for stamp in self._all if now - stamp < self._window]
        if len(self._all) >= self._global_max:
            return self._window - (now - self._all[0])
        recent = [stamp for stamp in self._failures.get(address, ()) if now - stamp < self._window]
        if recent:
            self._failures[address] = recent
        else:
            self._failures.pop(address, None)
        if len(recent) >= self._max:
            return self._window - (now - recent[0])
        return 0.0

    def failure(self, address: str) -> None:
        now = self._clock()
        self._failures.setdefault(address, []).append(now)
        self._failures.move_to_end(address)
        while len(self._failures) > self._max_tracked:
            self._failures.popitem(last=False)
        self._all.append(now)

    def success(self, address: str) -> None:
        self._failures.pop(address, None)


@dataclass
class DashboardSession:
    csrf: str
    expires: float


class SessionStore:
    """In-memory dashboard sessions, keyed by a hash of the cookie token."""

    def __init__(
        self,
        ttl_seconds: float,
        max_sessions: int = 16,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = ttl_seconds
        self._max = max_sessions
        self._clock = clock
        self._sessions: OrderedDict[str, DashboardSession] = OrderedDict()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create(self) -> tuple[str, DashboardSession]:
        token = secrets.token_urlsafe(32)
        session = DashboardSession(csrf=secrets.token_urlsafe(32),
                                   expires=self._clock() + self._ttl)
        self._sessions[self._key(token)] = session
        while len(self._sessions) > self._max:
            self._sessions.popitem(last=False)
        return token, session

    def get(self, token: str | None) -> DashboardSession | None:
        if not token:
            return None
        key = self._key(token)
        session = self._sessions.get(key)
        if session is None:
            return None
        if self._clock() >= session.expires:
            del self._sessions[key]
            return None
        return session

    def drop(self, token: str | None) -> None:
        if token:
            self._sessions.pop(self._key(token), None)

    def clear(self) -> None:
        self._sessions.clear()


def new_setup_code() -> str:
    """One-time code printed on the console to authorise first-run setup."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(12))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"
