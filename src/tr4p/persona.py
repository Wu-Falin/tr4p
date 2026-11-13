"""Per-install persona: what the trap looks like from the outside.

Banner, cookie name, site name and error pages are picked from the seed so
that two installs do not share a recognisable surface. In proxy mode the
persona additionally learns the real upstream's banner and "not found" page
and reuses them, so trap-generated responses match the protected site.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html import escape

from tr4p.seed import Seed

# (family, banner). Families decide which error-page layout is used.
_BANNERS = (
    ("nginx", "nginx"),
    ("nginx", "nginx/1.18.0 (Ubuntu)"),
    ("nginx", "nginx/1.22.1"),
    ("nginx", "nginx/1.24.0"),
    ("nginx", "nginx/1.26.2"),
    ("apache", "Apache"),
    ("apache", "Apache/2.4.52 (Ubuntu)"),
    ("apache", "Apache/2.4.57 (Debian)"),
    ("apache", "Apache/2.4.58 (Ubuntu)"),
    ("apache", "Apache/2.4.62 (Unix)"),
)

_COOKIE_NAMES = (
    "sid", "_sid", "session_ref", "visitor", "_vid", "vref", "site_session",
    "_sess", "uid_ref", "_pref", "browse_id", "_bid", "track_ref", "lb_route",
)

_NAME_HEADS = (
    "Nord", "Vela", "Halden", "Meridian", "Kestrel", "Arden", "Solvik",
    "Tessera", "Orbis", "Lumen", "Castel", "Brightline", "Ostra", "Fennec",
    "Marlow", "Quill", "Sable", "Tidewater", "Corvid", "Juniper",
)
_NAME_TAILS = (
    "Logistics", "Systems", "Labs", "Group", "Supply", "Analytics", "Freight",
    "Health", "Works", "Digital", "Trading", "Energy", "Partners", "Foods",
)

_REASONS = {
    302: "Found",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    408: "Request Timeout",
    413: "Request Entity Too Large",
    414: "URI Too Long",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}

_APACHE_TEXT = {
    400: "Your browser sent a request that this server could not understand.",
    401: "This server could not verify that you are authorized to access the "
         "document requested.",
    403: "You don't have permission to access this resource.",
    404: "The requested URL was not found on this server.",
    405: "The requested method is not allowed for this URL.",
    413: "The requested resource does not allow request data with the "
         "requested method, or the amount of data provided exceeds the limit.",
    500: "The server encountered an internal error or misconfiguration and "
         "was unable to complete your request.",
    502: "The proxy server received an invalid response from an upstream server.",
    503: "The server is temporarily unable to service your request due to "
         "maintenance downtime or capacity problems. Please try again later.",
    504: "The gateway did not receive a timely response from the upstream server.",
}


@dataclass
class LearnedPage:
    """A response captured from the real upstream, replayed for our own errors."""

    status: int
    content_type: str
    body: bytes


@dataclass
class Persona:
    family: str
    banner: str
    cookie_name: str
    site_name: str
    learned_banner: str | None = None
    learned_not_found: LearnedPage | None = field(default=None, repr=False)

    @classmethod
    def from_seed(cls, seed: Seed) -> "Persona":
        rng = seed.rng("persona")
        family, banner = rng.choice(_BANNERS)
        cookie = rng.choice(_COOKIE_NAMES)
        site = f"{rng.choice(_NAME_HEADS)} {rng.choice(_NAME_TAILS)}"
        return cls(family=family, banner=banner, cookie_name=cookie, site_name=site)

    @property
    def server_header(self) -> str:
        return self.learned_banner if self.learned_banner is not None else self.banner

    def learn_banner(self, value: str | None) -> None:
        """Adopt the protected site's Server header the first time we see one."""
        if self.learned_banner is None and value:
            self.learned_banner = value[:120]

    def learn_not_found(self, status: int, content_type: str, body: bytes) -> None:
        if self.learned_not_found is None and len(body) <= 65536:
            self.learned_not_found = LearnedPage(status, content_type, body)

    def error_page(self, status: int, host: str = "") -> tuple[str, bytes]:
        """Return (content_type, body) for an error this server answers itself."""
        if status == 404 and self.learned_not_found is not None:
            page = self.learned_not_found
            return page.content_type, page.body
        reason = _REASONS.get(status, "Error")
        banner = self.server_header
        family = _family_of(banner) or self.family
        if family == "apache":
            body = _apache_page(status, reason, banner, host)
        else:
            body = _nginx_page(status, reason, banner)
        return "text/html", body.encode("ascii", "replace")


def reason_phrase(status: int) -> str:
    return _REASONS.get(status, "Error")


def _family_of(banner: str) -> str | None:
    lowered = banner.lower()
    if "apache" in lowered:
        return "apache"
    if "nginx" in lowered or "openresty" in lowered:
        return "nginx"
    return None


def _nginx_page(status: int, reason: str, banner: str) -> str:
    title = f"{status} {reason}"
    footer = banner.split(" ")[0] if banner else "nginx"
    return (
        "<html>\r\n"
        f"<head><title>{title}</title></head>\r\n"
        "<body>\r\n"
        f"<center><h1>{title}</h1></center>\r\n"
        f"<hr><center>{escape(footer)}</center>\r\n"
        "</body>\r\n"
        "</html>\r\n"
    )


def _apache_page(status: int, reason: str, banner: str, host: str) -> str:
    text = _APACHE_TEXT.get(status, "The server could not complete your request.")
    name, _, port = host.partition(":")
    address = ""
    if banner and "/" in banner and name:
        address = (
            "<hr>\n"
            f"<address>{escape(banner)} Server at {escape(name)} "
            f"Port {escape(port or '80')}</address>\n"
        )
    return (
        '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
        "<html><head>\n"
        f"<title>{status} {reason}</title>\n"
        "</head><body>\n"
        f"<h1>{reason}</h1>\n"
        f"<p>{text}</p>\n"
        f"{address}"
        "</body></html>\n"
    )
