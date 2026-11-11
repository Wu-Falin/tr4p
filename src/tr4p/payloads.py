"""Recognise attack payloads in request data.

This is a detector, not a filter: nothing is blocked or rewritten. A match is
one signal among several. Patterns are kept specific on purpose; a missed
exotic payload costs little, a false match on normal traffic costs trust.
"""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

_FLAGS = re.IGNORECASE | re.DOTALL

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("sqli", re.compile(
        r"\bunion\b[\s/*()+]+(?:all[\s/*()+]+)?select\b"
        r"|\bselect\b.{1,80}?\bfrom\b.{1,40}?(?:information_schema|pg_catalog|sqlite_master|sysobjects|mysql\.user)"
        r"|['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*(?:=|like)\s*['\"]?\w+"
        r"|\b(?:or|and)\s+\d+\s*=\s*\d+\s*(?:--|#|/\*)"
        r"|\b(?:sleep|benchmark|pg_sleep|extractvalue|updatexml|load_file)\s*\("
        r"|\bwaitfor\s+delay\b"
        r"|;\s*(?:drop|alter|truncate)\s+(?:table|database)\b"
        r"|\binto\s+(?:out|dump)file\b",
        _FLAGS)),
    ("xss", re.compile(
        r"<\s*script\b"
        r"|<\s*(?:img|svg|iframe|body|video|audio|details|object|embed|input|a)\b[^>]*\bon\w+\s*="
        r"|\bjavascript\s*:\s*\S"
        r"|\bon(?:error|load|mouseover|focus|click|toggle)\s*=\s*['\"]?[^'\"\s>]*(?:alert|prompt|confirm|eval|fetch|document\.)",
        _FLAGS)),
    ("traversal", re.compile(
        r"(?:\.\.[/\\]){2,}"
        r"|/etc/(?:passwd|shadow|hosts)\b"
        r"|\b(?:boot|win)\.ini\b"
        r"|/proc/self/(?:environ|cmdline|maps)"
        r"|\bphp://(?:filter|input)"
        r"|\b(?:file|expect|gopher|dict|phar)://",
        _FLAGS)),
    ("command", re.compile(
        r"[;|&`]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|ping|sleep|powershell|cmd)\b(?:\s|$|[;|&`])"
        r"|\$\(\s*(?:cat|id|whoami|uname|curl|wget|sleep|ping)\b"
        r"|\(\)\s*\{\s*:?;?\s*\}\s*;",
        _FLAGS)),
    ("template", re.compile(
        r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}"
        r"|\$\{\s*\d+\s*\*\s*\d+\s*\}"
        r"|<%=\s*\d+\s*\*\s*\d+"
        r"|\{\{.{0,40}?(?:__class__|__globals__|config\.items)",
        _FLAGS)),
    ("lookup", re.compile(
        r"\$\{\s*jndi\s*:"
        r"|\$\{\s*(?:lower|upper|env|sys|date)\s*:"
        r"|\$\{\s*\$\{",
        _FLAGS)),
    ("entity", re.compile(
        r"<!entity\b|<!doctype[^>]{0,200}\[",
        _FLAGS)),
    ("metadata", re.compile(
        r"\b169\.254\.169\.254\b|\bmetadata\.google\.internal\b",
        _FLAGS)),
    ("operator", re.compile(
        r"\[\$(?:ne|gt|lt|gte|lte|regex|where|nin)\]"
        r"|\"\$(?:ne|gt|where|regex)\"\s*:",
        _FLAGS)),
    ("code", re.compile(
        r"\b(?:eval|system|passthru|shell_exec|popen|proc_open|base64_decode|assert)\s*\(\s*['\"$]"
        r"|<\?php\b",
        _FLAGS)),
)

# Characters at least one of which every pattern above needs. Plain URLs such
# as /products/42?page=2 skip the regular expressions entirely.
_TRIGGER = re.compile(
    r"[<>'\"`;|${}\[\]()\\]|\.\.|://|/etc/|\.ini\b|/proc/|169\.254|metadata\."
    r"|\bunion\b|--|/\*|\bwaitfor\b|\b(?:out|dump)file\b",
    re.IGNORECASE,
)

_HEADER_PATTERN = re.compile(
    r"\$\{\s*jndi\s*:|\$\{\s*(?:lower|upper|env)\s*:|\(\)\s*\{\s*:?;?\s*\}\s*;", _FLAGS
)

MAX_SCAN_CHARS = 16384


def decode(text: str) -> str:
    """URL-decode up to twice (double encoding is a common evasion)."""
    for _ in range(2):
        if "%" not in text and "+" not in text:
            break
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text


def find_payload(text: str) -> str | None:
    """Return the attack class found in text, or None."""
    if not text:
        return None
    text = decode(text[:MAX_SCAN_CHARS])
    if not _TRIGGER.search(text):
        return None
    for name, pattern in _PATTERNS:
        if pattern.search(text):
            return name
    return None


def find_header_payload(value: str) -> str | None:
    """Check a header value for the few payloads that travel in headers."""
    if "${" not in value and "() {" not in value and "(){" not in value:
        return None
    return "header" if _HEADER_PATTERN.search(value) else None
