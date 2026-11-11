"""Address whitelist for the defender's own testing hosts.

This is the only place where an address alone decides anything, and it only
ever switches detection *off*, by the defender's explicit choice.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from tr4p.config import parse_networks


class Whitelist:
    def __init__(self, entries: list[str]) -> None:
        self._networks = parse_networks(entries, "whitelist")
        self._lookup = lru_cache(maxsize=4096)(self._contains)

    def __bool__(self) -> bool:
        return bool(self._networks)

    def contains(self, address: str) -> bool:
        if not self._networks:
            return False
        return self._lookup(address)

    def _contains(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return any(ip.version == net.version and ip in net for net in self._networks)
