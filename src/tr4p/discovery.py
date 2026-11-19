"""Discovery documents and the made-up API they describe.

Automated clients like maps: an agent-style index, an API description, a
sitemap, a tool listing, a GraphQL schema. These documents are bait. They
describe an "internal" API that exists only as canned text, in a directory
nobody can reach except by reading the documents. Reading one is not
evidence (a harmless assistant may fetch such files). Acting on what it
lists is: that is the signal.

Everything is text computed from the seed. Nothing is executed or looked up;
a GraphQL query is only compared with one fixed shape and answered with
canned text. Documents carry a secret issued to the reading session, so
reuse of it elsewhere links sessions.
"""

from __future__ import annotations

import json
from html import escape

from tr4p.canary import Canaries
from tr4p.honeytoken import Honeytokens
from tr4p.loot import Loot
from tr4p.persona import Persona
from tr4p.seed import Seed

_NAMES = {
    "llms.txt": "llms", "openapi.json": "openapi", "swagger.json": "openapi",
    "api-docs": "openapi", "tool-manifest.json": "tools", "tools.json": "tools",
    "sitemap.xml": "sitemap", "graphql": "graphql",
}
_BLURB = {
    "users": "staff and customer accounts", "orders": "order history and fulfilment",
    "customers": "customer master records", "invoices": "billing documents",
    "keys": "service credentials", "tokens": "issued access tokens",
    "export": "bulk data export", "accounts": "account balances",
    "reports": "scheduled reports", "audit": "audit trail", "sessions": "active sessions",
    "payments": "payment records", "backups": "backup archives", "settings": "service settings",
}
_PEOPLE = ("Anna Keller", "David Novak", "Maria Silva", "Lena Meyer", "Omar Haddad",
           "Siti Wijaya", "Min-jun Kim", "Lucas Moreau")
_MAX_ROWS = 6


class Discovery:
    def __init__(self, seed: Seed, canaries: Canaries, honeytokens: Honeytokens,
                 persona: Persona) -> None:
        self._seed = seed
        self._canaries = canaries
        self._tokens = honeytokens
        self._persona = persona

    @staticmethod
    def kind_for(path: str) -> str | None:
        """Which document a path asks for, judged by its last segment."""
        return _NAMES.get(path.rsplit("/", 1)[-1].lower())

    # -------------------------------------------------------------- documents

    def document(self, kind: str, method: str, body: bytes | None, host: str,
                 session_key: str) -> Loot | None:
        key = session_key or None
        site = self._persona.site_name
        paths = list(self._canaries.current().api_paths)
        if kind == "llms":
            lines = [f"# {site}", "", "> Index for automated clients. These endpoints are internal.", "",
                     "## API"]
            lines += [f"- [{p.rsplit('/', 1)[-1].title()}]({p}): "
                      f"{_BLURB.get(p.rsplit('/', 1)[-1], 'internal data')}" for p in paths]
            lines += ["", "## Access", "Send the key in the X-Api-Key header.",
                      f"Test key: {self._tokens.issue('api_key', key)}", ""]
            return Loot(200, "text/plain; charset=utf-8", "\n".join(lines).encode("utf-8"), index=True)
        if kind == "openapi":
            document = {
                "openapi": "3.0.3",
                "info": {"title": f"{site} internal API", "version": "1.8.2",
                         "description": "Internal use only."},
                "servers": [{"url": f"https://{host.split(':')[0] or 'localhost'}"}],
                "paths": {p: {"get": {"summary": _BLURB.get(p.rsplit('/', 1)[-1], "internal data"),
                                      "security": [{"apiKey": []}],
                                      "responses": {"200": {"description": "OK"}}}} for p in paths},
                "components": {"securitySchemes": {"apiKey": {
                    "type": "apiKey", "in": "header", "name": "X-Api-Key",
                    "description": f"Example: {self._tokens.issue('api_key', key)}"}}},
            }
            return Loot(200, "application/json", json.dumps(document, indent=2).encode("ascii"), index=True)
        if kind == "tools":
            document = {"name": site, "version": "1", "tools": [
                {"name": p.rsplit("/", 1)[-1].replace("-", "_"), "method": "GET", "endpoint": p,
                 "description": _BLURB.get(p.rsplit("/", 1)[-1], "internal data"),
                 "auth": {"header": "X-Api-Key"}} for p in paths[:6]]}
            return Loot(200, "application/json", json.dumps(document, indent=2).encode("ascii"), index=True)
        if kind == "sitemap":
            base = f"https://{host.split(':')[0] or 'localhost'}"
            urls = "".join(f"<url><loc>{escape(base + p)}</loc><priority>0.4</priority></url>" for p in paths)
            xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                   f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>\n')
            return Loot(200, "application/xml", xml.encode("ascii", "xmlcharrefreplace"), index=True)
        if kind == "graphql":
            return self._graphql(method, body, paths)
        return None

    def _graphql(self, method: str, body: bytes | None, paths: list[str]) -> Loot:
        """Canned answers. The query text is only compared with one shape
        (an introspection request); it is never parsed or run."""
        names = [p.rsplit("/", 1)[-1] for p in paths]
        text = (body or b"")[:4096].decode("utf-8", "replace")
        if method == "GET" and not text:
            document = {"errors": [{"message": "Must provide query string."}]}
        elif "__schema" in text or "__type" in text:
            fields = [{"name": name, "args": [], "type": {"kind": "LIST", "name": None}} for name in names]
            document = {"data": {"__schema": {
                "queryType": {"name": "Query"}, "mutationType": None,
                "types": [{"kind": "OBJECT", "name": "Query", "fields": fields},
                          {"kind": "SCALAR", "name": "String", "fields": None}]}}}
        else:
            document = {"data": None, "errors": [{"message": "Unauthorized: missing API key"}]}
        return Loot(200, "application/json", json.dumps(document).encode("ascii"), index=True)

    # -------------------------------------------------------------- endpoints

    def endpoint(self, path: str, rotation: int, session_key: str) -> Loot:
        """Answer a request inside the made-up API: listed endpoints give
        canned data that leads to the next one, anything else is unknown."""
        built = self._canaries.set_for(rotation)
        clean = path.rstrip("/") or "/"
        if built is None or clean not in built.api_paths:
            return Loot(404, "application/json", b'{"error":"not_found"}')
        key = session_key or None
        name = clean.rsplit("/", 1)[-1]
        rng = self._seed.rng("endpoint", clean)
        rows = [{"id": 1000 + index, "name": rng.choice(_PEOPLE),
                 "email": f"user{rng.randrange(100, 999)}@example.com",
                 "updated": f"2025-{rng.randrange(1, 13):02d}-{rng.randrange(1, 29):02d}"}
                for index in range(rng.randrange(3, _MAX_ROWS + 1))]
        document: dict = {"data": rows, "total": len(rows) + rng.randrange(40, 900)}
        if name in ("keys", "tokens"):
            document["data"] = [{"name": "reporting", "key": self._tokens.issue("api_key", key),
                                 "scope": "read"}]
        later = [p for p in built.api_paths if p != clean]
        if later:
            document["links"] = {"next": rng.choice(later)}
        return Loot(200, "application/json", json.dumps(document, indent=2).encode("ascii"))
