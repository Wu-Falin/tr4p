"""Honeytokens: fake secrets planted in bait files.

They look valuable and work nowhere. Nobody can know one without having read
hidden bait first, so seeing one come back in a request is strong evidence
on its own.
"""

from __future__ import annotations

from dataclasses import dataclass

from tr4p.seed import Seed

_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_UPPER32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_HEX = "0123456789abcdef"
_PASS_WORDS = ("Harbor", "Falcon", "Granite", "Orchid", "Summit", "Velvet", "Copper", "Lantern")
_KEY_PREFIXES = ("sk_live_", "key_", "api_", "tok_", "live_")

MIN_TOKEN_LENGTH = 12


@dataclass(frozen=True)
class Honeytoken:
    name: str
    value: str


class Honeytokens:
    """The fixed set of fake secrets for this install."""

    def __init__(self, seed: Seed) -> None:
        rng = seed.rng("honeytokens")

        def pick(alphabet: str, length: int) -> str:
            return "".join(rng.choice(alphabet) for _ in range(length))

        tokens = (
            Honeytoken("cloud_access_key", "AKIA" + pick(_UPPER32, 16)),
            Honeytoken("cloud_secret_key", pick(_ALNUM, 40)),
            Honeytoken("api_key", rng.choice(_KEY_PREFIXES) + pick(_ALNUM, 28)),
            Honeytoken("db_password", pick(_ALNUM, 18)),
            Honeytoken("admin_password",
                       f"{rng.choice(_PASS_WORDS)}{rng.randrange(1000, 9999)}{pick(_ALNUM, 4)}"),
            Honeytoken("jwt_secret", pick(_HEX, 48)),
            Honeytoken("deploy_token", "dpl_" + pick(_ALNUM, 26)),
            Honeytoken("smtp_password", pick(_ALNUM, 16)),
        )
        self._tokens = tokens
        self._by_name = {token.name: token.value for token in tokens}

    def all(self) -> tuple[Honeytoken, ...]:
        return self._tokens

    def value(self, name: str) -> str:
        return self._by_name[name]

    def find(self, *haystacks: str) -> Honeytoken | None:
        """Return the first planted secret found in any of the given texts."""
        for text in haystacks:
            if not text or len(text) < MIN_TOKEN_LENGTH:
                continue
            for token in self._tokens:
                if token.value in text:
                    return token
        return None
