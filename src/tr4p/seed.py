"""Per-install secret seed.

Everything an attacker could use to recognise an install (canary paths,
cookie names, banners, fake credentials) is derived from this secret, so
reading the source code does not reveal what a given deployment looks like.
"""

from __future__ import annotations

import hashlib
import hmac
import random
import secrets
from pathlib import Path

from tr4p.fsutil import write_private

SECRET_BYTES = 32


class Seed:
    """Wraps the install secret and derives independent values from it."""

    def __init__(self, secret: bytes) -> None:
        if len(secret) < SECRET_BYTES:
            raise ValueError("seed secret is too short")
        self._secret = bytes(secret)

    @classmethod
    def generate(cls) -> "Seed":
        return cls(secrets.token_bytes(SECRET_BYTES))

    @classmethod
    def load(cls, path: Path) -> "Seed":
        text = path.read_text(encoding="ascii").strip()
        try:
            return cls(bytes.fromhex(text))
        except ValueError as exc:
            raise ValueError(f"{path.name} is not a valid seed file") from exc

    def save(self, path: Path) -> None:
        write_private(path, self._secret.hex().encode("ascii") + b"\n")

    def digest(self, label: str, *parts: object) -> bytes:
        """HMAC-SHA256 over a label and length-prefixed parts.

        Length prefixes keep ("ab", "c") and ("a", "bc") from colliding.
        """
        mac = hmac.new(self._secret, digestmod=hashlib.sha256)
        for item in (label, *parts):
            raw = item if isinstance(item, bytes) else str(item).encode("utf-8")
            mac.update(len(raw).to_bytes(4, "big"))
            mac.update(raw)
        return mac.digest()

    def hex(self, label: str, *parts: object, length: int = 16) -> str:
        return self.digest(label, *parts).hex()[:length]

    def rng(self, label: str, *parts: object) -> random.Random:
        """Deterministic generator for cosmetic variation (never for secrets)."""
        return random.Random(int.from_bytes(self.digest(label, *parts), "big"))

    def sign(self, label: str, message: bytes, size: int = 12) -> bytes:
        return self.digest(label, message)[:size]

    def verify(self, label: str, message: bytes, tag: bytes) -> bool:
        return hmac.compare_digest(self.sign(label, message, len(tag)), tag)
