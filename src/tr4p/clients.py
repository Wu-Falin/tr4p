"""Client classification from request headers.

Nothing here decides anything alone: a user agent is trivially forged, so it
only ever counts as one weak signal that has to be backed by another.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Mapping

# Tools whose default user agent announces an attack or scanning tool.
SCANNER_AGENTS = (
    "sqlmap", "nikto", "nuclei", "nmap", "masscan", "zgrab", "gobuster",
    "dirbuster", "dirb", "ffuf", "fuzz faster", "wfuzz", "feroxbuster",
    "wpscan", "acunetix", "nessus", "openvas", "hydra", "zaproxy", "owasp",
    "whatweb", "joomscan", "commix", "arachni", "w3af", "metasploit", "havij",
    "netsparker", "qualys", "jaeles", "dalfox", "xsstrike", "wapiti",
    "skipfish", "appscan", "webinspect", "nettacker", "zmeu", "morfeus",
    "l9explore", "l9tcpid", "censysinspect", "expanse", "interactsh",
)

# HTTP libraries and automation frameworks. Common in monitoring too, hence
# the low weight.
GENERIC_CLIENTS = (
    "python-requests", "python-urllib", "python-httpx", "aiohttp", "curl/",
    "wget/", "go-http-client", "java/", "okhttp", "libwww-perl", "lwp::",
    "node-fetch", "axios/", "undici", "guzzlehttp", "scrapy", "mechanize",
    "http.rb", "restsharp", "postmanruntime", "insomnia", "winhttp",
    "powershell", "headlesschrome", "phantomjs", "selenium", "playwright",
    "puppeteer", "httpclient", "faraday", "reqwest", "hackney",
)

_DECLARED_BOT_MARKS = ("bot", "crawler", "spider", "slurp", "+http")
_BROWSER_MARKS = ("chrome/", "firefox/", "safari/", "edg/", "opr/")

_VALUE_HEADERS = (
    "user-agent", "accept-language", "accept-encoding",
    "sec-ch-ua", "sec-ch-ua-platform", "sec-ch-ua-mobile",
)
_ORDER_HEADERS = frozenset(
    {"host", "connection", "user-agent", "accept", "accept-encoding", "accept-language"}
)

_ASSET_EXTENSIONS = frozenset({
    "css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "webp", "avif",
    "svg", "ico", "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3",
    "ogg", "wav", "pdf",
})
_ASSET_DESTINATIONS = frozenset({"image", "style", "script", "font", "video", "audio", "track"})


def classify_agent(user_agent: str, extra_scanners: Iterable[str] = ()) -> tuple[str, str]:
    """Return (category, matched name).

    Categories: scanner, generic, declared_bot, browser, other.
    """
    lowered = user_agent.strip().lower()
    if not lowered:
        return "generic", "empty user agent"
    for name in SCANNER_AGENTS:
        if name in lowered:
            return "scanner", name
    for name in extra_scanners:
        if name and name.lower() in lowered:
            return "scanner", name.lower()
    for name in GENERIC_CLIENTS:
        if name in lowered:
            return "generic", name.rstrip("/(")
    for mark in _DECLARED_BOT_MARKS:
        if mark in lowered:
            return "declared_bot", mark
    if lowered.startswith("mozilla/") and any(mark in lowered for mark in _BROWSER_MARKS):
        return "browser", "browser"
    return "other", ""


def browser_header_anomaly(headers: Mapping[str, str], http_version: tuple[int, int]) -> str | None:
    """Explain why a browser-looking request does not behave like a browser."""
    if "accept" not in headers:
        return "browser user agent without Accept header"
    if "accept-language" not in headers:
        return "browser user agent without Accept-Language header"
    if "accept-encoding" not in headers:
        return "browser user agent without Accept-Encoding header"
    if http_version < (1, 1):
        return "browser user agent over HTTP/1.0"
    return None


def fingerprint(headers: Mapping[str, str], http_version: tuple[int, int]) -> str:
    """Stable hash of what a client's request headers look like.

    Uses values that stay constant across a client's requests plus the
    relative order of core headers, which differs between HTTP stacks.
    """
    digest = hashlib.sha256()
    for name in _VALUE_HEADERS:
        digest.update(headers.get(name, "\x00").encode("utf-8", "replace"))
        digest.update(b"\n")
    order = [key.lower() for key in headers.keys() if key.lower() in _ORDER_HEADERS]
    digest.update(",".join(order).encode("ascii", "replace"))
    digest.update(b"|%d.%d" % http_version)
    return digest.hexdigest()[:20]


def is_asset_request(path: str, headers: Mapping[str, str]) -> bool:
    """True for sub-resources (styles, scripts, images, fonts, media)."""
    destination = headers.get("sec-fetch-dest", "")
    if destination and destination.lower() in _ASSET_DESTINATIONS:
        return True
    dot = path.rfind(".")
    if dot == -1 or "/" in path[dot:]:
        return False
    return path[dot + 1:].lower() in _ASSET_EXTENSIONS
