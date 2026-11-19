"""Honeytokens: fake secrets planted in bait files.

They look valuable and work nowhere. Nobody can know one without having read
hidden bait first, so seeing one come back in a request is strong evidence
on its own.

Every token is made at run time from the install seed. Each one ends in a
short marker (an id and a keyed tag) in the token's own alphabet. When a
token is handed to a particular session, the id says which one, so a secret
that turns up in a different session shows the two belong together. A token
that was altered, or whose id this process no longer remembers, is still
recognised as planted; only the link to its origin is lost.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from tr4p.seed import Seed

_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_UPPER32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_HEX = "0123456789abcdef"
_PASS_WORDS = ("Harbor", "Falcon", "Granite", "Orchid", "Summit", "Velvet", "Copper", "Lantern")
_KEY_PREFIXES = ("sk_live_", "key_", "api_", "tok_", "live_")

MIN_TOKEN_LENGTH = 12
ID_CHARS = 4
TAG_CHARS = 4
TAIL = ID_CHARS + TAG_CHARS
MAX_ORIGINS = 50000


@dataclass(frozen=True)
class Honeytoken:
    name: str
    value: str          # the install-wide form of the token


@dataclass(frozen=True)
class Found:
    name: str
    value: str          # what was matched, as it appeared
    origin: str | None  # session the secret was issued to, if known
    install: bool       # the install-wide form, not issued to one session


@dataclass(frozen=True)
class _Spec:
    name: str
    alphabet: str
    fixed: str          # everything before the marker


class Honeytokens:
    """The fixed set of fake secrets for this install."""

    def __init__(self, seed: Seed) -> None:
        rng = seed.rng("honeytokens")

        def pick(alphabet: str, length: int) -> str:
            return "".join(rng.choice(alphabet) for _ in range(length))

        self._seed = seed
        self._specs = (
            _Spec("cloud_access_key", _UPPER32, "AKIA" + pick(_UPPER32, 8)),
            _Spec("cloud_secret_key", _ALNUM, pick(_ALNUM, 32)),
            _Spec("api_key", _ALNUM, rng.choice(_KEY_PREFIXES) + pick(_ALNUM, 20)),
            _Spec("db_password", _ALNUM, pick(_ALNUM, 10)),
            _Spec("admin_password", _ALNUM,
                  f"{rng.choice(_PASS_WORDS)}{rng.randrange(1000, 9999)}{pick(_ALNUM, 6)}"),
            _Spec("jwt_secret", _HEX, pick(_HEX, 40)),
            _Spec("deploy_token", _ALNUM, "dpl_" + pick(_ALNUM, 18)),
            _Spec("smtp_password", _ALNUM, pick(_ALNUM, 12)),
        )
        self._by_name = {spec.name: spec for spec in self._specs}
        self._origins: OrderedDict[tuple[str, str], str] = OrderedDict()
        self._tokens = tuple(Honeytoken(spec.name, self.issue(spec.name)) for spec in self._specs)

    # ---------------------------------------------------------------- making

    def _marker(self, spec: _Spec, session_key: str | None) -> tuple[str, str]:
        raw = (self._seed.digest("token-install", spec.name) if session_key is None
               else self._seed.digest("token-id", session_key))
        ident = "".join(spec.alphabet[b % len(spec.alphabet)] for b in raw[:ID_CHARS])
        tag_raw = self._seed.digest("token-tag", spec.name, ident)
        tag = "".join(spec.alphabet[b % len(spec.alphabet)] for b in tag_raw[:TAG_CHARS])
        return ident, tag

    def issue(self, name: str, session_key: str | None = None) -> str:
        """The token to show a session, or the install-wide one when no
        session is given."""
        spec = self._by_name[name]
        ident, tag = self._marker(spec, session_key)
        if session_key is not None:
            key = (name, ident)
            previous = self._origins.get(key)
            # Ids are short, so two sessions can share one. Then a returning
            # secret cannot say which session it came from: link neither.
            self._origins[key] = session_key if previous in (None, session_key) else ""
            self._origins.move_to_end(key)
            while len(self._origins) > MAX_ORIGINS:
                self._origins.popitem(last=False)
        return spec.fixed + ident + tag

    def all(self) -> tuple[Honeytoken, ...]:
        return self._tokens

    def value(self, name: str) -> str:
        """The install-wide form (used where no session is involved)."""
        return self._tokens[[t.name for t in self._tokens].index(name)].value

    # --------------------------------------------------------------- finding

    def find(self, *haystacks: str) -> Found | None:
        """Return the first planted secret found in any of the given texts."""
        for text in haystacks:
            if not text or len(text) < MIN_TOKEN_LENGTH:
                continue
            for spec in self._specs:
                start = text.find(spec.fixed)
                if start < 0:
                    continue
                end = start + len(spec.fixed)
                return self._identify(spec, text[start:end], text[end:end + TAIL])
        return None

    def _identify(self, spec: _Spec, fixed: str, tail: str) -> Found:
        if len(tail) == TAIL and all(char in spec.alphabet for char in tail):
            ident, tag = tail[:ID_CHARS], tail[ID_CHARS:]
            expected = self._seed.digest("token-tag", spec.name, ident)
            if tag == "".join(spec.alphabet[b % len(spec.alphabet)] for b in expected[:TAG_CHARS]):
                if (ident, tag) == self._marker(spec, None):
                    return Found(spec.name, fixed + tail, None, True)
                return Found(spec.name, fixed + tail, self._origins.get((spec.name, ident)) or None, False)
        return Found(spec.name, fixed + tail, None, False)
