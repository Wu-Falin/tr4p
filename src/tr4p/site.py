"""Built-in site for standalone mode.

When there is no real application behind the trap, this serves a small,
plausible company site so there is something to probe. It is a placeholder
with no functionality: the login form accepts nothing.
"""

from __future__ import annotations

from html import escape

from tr4p.persona import Persona
from tr4p.seed import Seed

_ACCENTS = ("#1f6feb", "#0f766e", "#b45309", "#7c3aed", "#be123c", "#0369a1", "#4d7c0f")
_TAGLINES = (
    "Reliable operations for growing teams.",
    "Moving goods and data, on time.",
    "Tools your back office can depend on.",
    "Service you can plan around.",
    "Infrastructure for everyday business.",
)

_CSS = """\
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#1f2933;background:#f7f8fa;line-height:1.55}
header{background:#fff;border-bottom:1px solid #e3e7ec}
.wrap{max-width:920px;margin:0 auto;padding:0 20px}
.bar{display:flex;align-items:center;gap:24px;height:64px}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;color:#111;text-decoration:none}
nav{margin-left:auto;display:flex;gap:18px}
nav a{color:#44505c;text-decoration:none}
nav a:hover{color:ACCENT}
main{padding:48px 0}
h1{font-size:2rem;margin:0 0 12px}
.lead{font-size:1.1rem;color:#52606d;max-width:60ch}
.card{background:#fff;border:1px solid #e3e7ec;border-radius:8px;padding:24px;max-width:380px}
label{display:block;font-size:.9rem;margin:14px 0 4px}
input{width:100%;padding:9px 10px;border:1px solid #cbd2d9;border-radius:6px;font:inherit}
button{margin-top:18px;padding:9px 16px;border:0;border-radius:6px;background:ACCENT;color:#fff;font:inherit;cursor:pointer}
.error{color:#b42318;margin:0 0 8px}
footer{padding:28px 0;color:#7b8794;font-size:.85rem}
"""

_LOGO = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">'
    '<rect width="32" height="32" rx="7" fill="ACCENT"/>'
    '<path d="M9 22V10h4l3 7 3-7h4v12h-3v-7l-3 7h-2l-3-7v7z" fill="#fff"/></svg>'
)


class BuiltinSite:
    def __init__(self, persona: Persona, seed: Seed) -> None:
        rng = seed.rng("builtin-site")
        self._name = persona.site_name
        self._accent = rng.choice(_ACCENTS)
        self._tagline = rng.choice(_TAGLINES)
        self._year = 2024 + rng.randrange(2)

    def respond(self, method: str, path: str) -> tuple[int, str, bytes] | None:
        """Return (status, content type, body), or None for "not found"."""
        if path == "/assets/site.css":
            return 200, "text/css", _CSS.replace("ACCENT", self._accent).encode("ascii")
        if path == "/assets/logo.svg":
            return 200, "image/svg+xml", _LOGO.replace("ACCENT", self._accent).encode("ascii")
        if path == "/":
            return 200, "text/html; charset=utf-8", self._page(
                "Home",
                f"<h1>{escape(self._name)}</h1>"
                f'<p class="lead">{escape(self._tagline)}</p>',
            )
        if path == "/about":
            return 200, "text/html; charset=utf-8", self._page(
                "About",
                "<h1>About us</h1>"
                f'<p class="lead">{escape(self._name)} supports customers across several '
                "regions with a small, dedicated team.</p>",
            )
        if path == "/contact":
            return 200, "text/html; charset=utf-8", self._page(
                "Contact",
                "<h1>Contact</h1>"
                '<p class="lead">Existing customers can reach support through the '
                "customer portal.</p>",
            )
        if path == "/login":
            error = '<p class="error">Invalid username or password.</p>' if method == "POST" else ""
            return 200, "text/html; charset=utf-8", self._page(
                "Sign in",
                '<h1>Sign in</h1><div class="card">'
                f'{error}<form method="post" action="/login">'
                '<label for="u">Username</label><input id="u" name="username" autocomplete="username">'
                '<label for="p">Password</label>'
                '<input id="p" name="password" type="password" autocomplete="current-password">'
                "<button>Sign in</button></form></div>",
            )
        return None

    def _page(self, title: str, content: str) -> bytes:
        name = escape(self._name)
        return (
            "<!doctype html>\n"
            '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{escape(title)} | {name}</title>\n"
            '<link rel="icon" href="/assets/logo.svg" type="image/svg+xml">\n'
            '<link rel="stylesheet" href="/assets/site.css">\n</head>\n<body>\n'
            '<header><div class="wrap bar">'
            f'<a class="brand" href="/"><img src="/assets/logo.svg" alt="" width="28" height="28">{name}</a>'
            '<nav><a href="/about">About</a><a href="/contact">Contact</a>'
            '<a href="/login">Sign in</a></nav></div></header>\n'
            f'<main><div class="wrap">{content}</div></main>\n'
            f'<footer><div class="wrap">&copy; {self._year} {name}</div></footer>\n'
            "</body>\n</html>\n"
        ).encode("utf-8")
