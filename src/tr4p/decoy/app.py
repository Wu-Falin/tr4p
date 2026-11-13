"""The emulated application behind the decoy.

One class answers every request with text computed from the decoy's seed.
Four profiles change how the same fake company presents itself: a generic
web app, a PHP-style site, a WordPress-style blog and a JSON API.

Hard rules, the same as everywhere in the trap:

* Input is only compared with fixed shapes and echoed back escaped. Nothing
  is executed, evaluated, used as a file name or sent to a database.
* No outbound requests. The "fetch a URL" endpoint always returns the same
  canned failure without looking at the network.
* Facts are fixed by the seed, so a session always sees the same people,
  orders and secrets. The only per-session state is "signed in or not".
"""

from __future__ import annotations

import json
import random
from collections import OrderedDict
from dataclasses import dataclass, field
from html import escape
from typing import Any
from urllib.parse import parse_qs

from tr4p.decoy.synth import Dataset
from tr4p.site import BuiltinSite

MAX_SESSIONS = 5000
MAX_ROWS = 50
PROFILES = ("generic", "php", "wordpress", "api")
HTML = "text/html; charset=utf-8"
JSON = "application/json; charset=utf-8"


@dataclass
class Reply:
    status: int
    content_type: str
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)
    touch: str = ""      # set when something marked sensitive was reached


def _json(document: Any, status: int = 200, touch: str = "") -> Reply:
    body = json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")
    return Reply(status, JSON, body, touch=touch)


def _redirect(location: str) -> Reply:
    return Reply(302, HTML, b"", {"Location": location})


class DecoyApp:
    def __init__(self, profile: str, seed: bytes, look: dict, tokens: dict[str, str],
                 schema: dict | None = None) -> None:
        if profile not in PROFILES:
            raise ValueError("unknown decoy profile")
        self.profile = profile
        self._seed = seed
        self._look = look
        self._tokens = tokens
        self._site = BuiltinSite(look=look)
        self._data = Dataset(random.Random(seed))
        self._tables = self._clean_schema(schema)
        self._sessions: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.served = 0
        self.touches = 0

    # ------------------------------------------------------------------ state

    def _state(self, sid: str) -> dict[str, Any]:
        state = self._sessions.get(sid)
        if state is None:
            state = self._sessions[sid] = {"signed_in": False}
            while len(self._sessions) > MAX_SESSIONS:
                self._sessions.popitem(last=False)
        else:
            self._sessions.move_to_end(sid)
        return state

    def wipe(self, sid: str) -> bool:
        return self._sessions.pop(sid, None) is not None

    def stats(self) -> dict[str, Any]:
        return {"profile": self.profile, "served": self.served, "touches": self.touches,
                "sessions": len(self._sessions), "tables": len(self._tables)}

    @staticmethod
    def _clean_schema(schema: dict | None) -> dict[str, list[tuple[str, str]]]:
        tables: dict[str, list[tuple[str, str]]] = {}
        for table in (schema or {}).get("tables", [])[:200]:
            columns = [(str(c["name"]), str(c["type"])) for c in table.get("columns", [])[:200]]
            if columns:
                tables[str(table["name"])] = columns
        return tables

    # ---------------------------------------------------------------- routing

    def handle(self, method: str, path: str, query: str, body: bytes, sid: str) -> Reply:
        self.served += 1
        state = self._state(sid)
        params = {key: values[0] for key, values in parse_qs(query).items()}
        route = getattr(self, f"_serve_{self.profile}")
        reply = route(method, path, params, body, state)
        if reply is None:
            reply = self._not_found()
        if reply.touch:
            self.touches += 1
        if self.profile in ("php", "wordpress"):
            reply.headers.setdefault("X-Powered-By", "PHP/8.2.18")
        return reply

    def _not_found(self) -> Reply:
        if self.profile == "api":
            return _json({"error": "not_found"}, 404)
        return Reply(404, HTML, self._page("Not found", "<h1>Page not found</h1>"))

    # --------------------------------------------------------------- profiles

    def _serve_generic(self, method, path, params, body, state) -> Reply | None:
        if path in ("/login", "/admin/login"):
            return self._login(method, body, state, "/login", "/admin")
        if path == "/logout":
            state["signed_in"] = False
            return _redirect("/")
        if path.startswith("/admin"):
            return self._admin(path[len("/admin"):].strip("/"), state, "/login", "/admin/")
        if path.startswith("/api/"):
            return self._api(path[len("/api/"):].strip("/"), params)
        return self._front(method, path)

    def _serve_php(self, method, path, params, body, state) -> Reply | None:
        if path in ("/", "/index.php"):
            page = params.get("page", "home")
            mapping = {"home": "/", "about": "/about", "contact": "/contact"}
            return self._front(method, mapping.get(page, "/missing"))
        if path == "/login.php":
            return self._login(method, body, state, "/login.php", "/admin/index.php")
        if path == "/phpinfo.php":
            rows = "".join(f"<tr><td>{name}</td><td>{value}</td></tr>" for name, value in (
                ("PHP Version", "8.2.18"), ("System", "Linux web01 5.15.0 x86_64"),
                ("Server API", "FPM/FastCGI"), ("DOCUMENT_ROOT", "/var/www/html"),
                ("DB_HOST", "127.0.0.1"), ("DB_PASSWORD", escape(self._tokens.get("db_password", ""))),
            ))
            return Reply(200, HTML, self._page("phpinfo()", f"<h1>PHP Version 8.2.18</h1><table>{rows}</table>"),
                         touch="phpinfo page")
        if path.startswith("/admin/"):
            name = path[len("/admin/"):]
            sub = {"index.php": "", "users.php": "users", "export.php": "export.csv",
                   "db.php": "db"}.get(name)
            return None if sub is None else self._admin(sub, state, "/login.php", "/admin/",
                                                         suffix=".php")
        if path == "/api.php":
            return self._api(params.get("r", ""), params)
        if path.startswith("/assets/"):
            return self._front(method, path)
        return None

    def _serve_wordpress(self, method, path, params, body, state) -> Reply | None:
        if path.startswith("/assets/"):
            return self._front(method, path)
        if path == "/" and "author" in params:
            return _redirect("/author/admin/")
        if path == "/":
            posts = "".join(
                f'<article lang="{locale}"><h2><a href="/?p={index}">{escape(title)}</a></h2>'
                f"<p>{escape(self._data.companies[index % len(self._data.companies)])}</p></article>"
                for index, (locale, title) in enumerate(self._data.posts, start=1)
            )
            return Reply(200, HTML, self._page("Blog", posts,
                                               head='<meta name="generator" content="WordPress 6.5.3">'))
        if path == "/wp-login.php":
            return self._login(method, body, state, "/wp-login.php", "/wp-admin/",
                               user_field="log", password_field="pwd")
        if path.startswith("/wp-admin"):
            sub = path[len("/wp-admin"):].strip("/")
            sub = {"": "", "users.php": "users", "export.php": "export.csv"}.get(sub)
            return None if sub is None else self._admin(sub, state, "/wp-login.php", "/wp-admin/",
                                                         suffix=".php")
        if path == "/wp-json/wp/v2/users":
            return _json([{"id": p.id, "name": p.name, "slug": p.login,
                           "link": f"/author/{p.login}/"} for p in self._data.people[:10]],
                         touch="user list (wp-json)")
        if path == "/wp-json/wp/v2/posts":
            return _json([{"id": index, "title": {"rendered": title}, "lang": locale}
                          for index, (locale, title) in enumerate(self._data.posts, start=1)])
        if path == "/xmlrpc.php":
            if method != "POST":
                return Reply(405, "text/plain", b"XML-RPC server accepts POST requests only.")
            fault = ('<?xml version="1.0" encoding="UTF-8"?><methodResponse><fault><value><struct>'
                     "<member><name>faultCode</name><value><int>403</int></value></member>"
                     "<member><name>faultString</name><value><string>Incorrect username or password."
                     "</string></value></member></struct></value></fault></methodResponse>")
            return Reply(200, "text/xml; charset=UTF-8", fault.encode("utf-8"))
        if path == "/readme.html":
            return Reply(200, HTML, self._page("WordPress", "<h1>WordPress</h1><p>Version 6.5</p>"))
        if path.startswith("/author/"):
            return Reply(200, HTML, self._page("Author", f"<h1>{escape(self._data.people[0].name)}</h1>"))
        return None

    def _api_profile_index(self) -> Reply:
        return _json({"service": self._look["name"], "version": "2.4.1",
                      "endpoints": ["/api/v1/health", "/api/v1/users", "/api/v1/orders",
                                    "/api/v1/keys", "/api/v1/fetch", "/api/v1/tables"]})

    def _api(self, name: str, params: dict[str, str]) -> Reply | None:
        """JSON data endpoints shared by all profiles."""
        people, orders = self._data.people, self._data.orders
        if name == "health":
            return _json({"status": "ok"})
        if name == "users":
            return _json({"total": len(people), "items": [vars(p) for p in people[:MAX_ROWS]]},
                         touch="user list")
        if name.startswith("users/") and name[6:].isdigit():
            index = int(name[6:])
            if 1 <= index <= len(people):
                return _json(vars(people[index - 1]), touch="user record")
            return _json({"error": "not_found"}, 404)
        if name == "orders":
            return _json({"total": len(orders), "items": [vars(o) for o in orders[:MAX_ROWS]]},
                         touch="order list")
        if name == "keys":
            return _json({"keys": [{"name": "reporting", "key": self._tokens.get("api_key", ""),
                                    "scope": "read"}]}, touch="API keys")
        if name == "fetch":
            # Looks like a server-side fetch. It never touches the network.
            return _json({"error": "upstream_timeout", "detail": "no response within 10 s",
                          "url": params.get("url", "")[:200]}, 504, touch="server-side fetch attempt")
        if name == "tables":
            return _json({"tables": sorted(self._tables)}, touch="table list")
        if name.startswith("tables/"):
            return self._table(name[7:])
        return None

    def _serve_api(self, method, path, params, body, state) -> Reply | None:
        if path in ("/", "/api", "/api/v1", "/api/v1/"):
            return self._api_profile_index()
        if path == "/openapi.json":
            return _json({"openapi": "3.0.3", "info": {"title": self._look["name"], "version": "2.4.1"},
                          "paths": {f"/api/v1/{name}": {} for name in ("health", "users", "orders", "keys")}})
        if path.startswith("/api/v1/"):
            return self._api(path[len("/api/v1/"):].strip("/"), params)
        return None

    # ---------------------------------------------------------- shared pieces

    def _front(self, method: str, path: str) -> Reply | None:
        result = self._site.respond(method, path)
        if result is None:
            return None
        status, content_type, body = result
        return Reply(status, content_type, body)

    def _login(self, method: str, body: bytes, state: dict, here: str, target: str,
               user_field: str = "username", password_field: str = "password") -> Reply:
        failed = False
        if method == "POST":
            fields = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
            password = "".join(fields.get(password_field, [""]))
            if password and password == self._tokens.get("admin_password"):
                state["signed_in"] = True
                return Reply(302, HTML, b"", {"Location": target}, touch="sign-in with planted credentials")
            failed = True
        error = '<p class="error">Invalid username or password.</p>' if failed else ""
        form = (
            f'<h1>Sign in</h1><div class="card">{error}<form method="post" action="{here}">'
            f'<label for="u">Username</label><input id="u" name="{user_field}" autocomplete="username">'
            f'<label for="p">Password</label><input id="p" name="{password_field}" type="password">'
            "<button>Sign in</button></form></div>"
        )
        return Reply(200, HTML, self._page("Sign in", form))

    def _admin(self, sub: str, state: dict, login: str, base: str, suffix: str = "") -> Reply | None:
        if not state["signed_in"]:
            return _redirect(login)
        people = self._data.people
        if sub == "":
            links = "".join(f'<li><a href="{base}{name}{suffix}">{label}</a></li>' for name, label in
                            (("users", "Users"), ("export", "Export users"), ("db", "Database")))
            return Reply(200, HTML, self._page("Administration", f"<h1>Administration</h1><ul>{links}</ul>"),
                         touch="admin area")
        if sub == "users":
            rows = "".join(
                f'<tr lang="{p.locale}"><td>{p.id}</td><td>{escape(p.name)}</td><td>{p.email}</td>'
                f"<td>{p.role}</td><td>{p.phone}</td></tr>" for p in people)
            table = f"<h1>Users</h1><table><tr><th>ID</th><th>Name</th><th>E-mail</th><th>Role</th><th>Phone</th></tr>{rows}</table>"
            return Reply(200, HTML, self._page("Users", table), touch="user table")
        if sub in ("export", "export.csv"):
            lines = ["id,name,email,role,phone"] + [
                f"{p.id},{p.name},{p.email},{p.role},{p.phone}" for p in people]
            return Reply(200, "text/csv; charset=utf-8", ("\n".join(lines) + "\n").encode("utf-8"),
                         {"Content-Disposition": 'attachment; filename="users.csv"'}, touch="user export")
        if sub == "db":
            names = sorted(self._tables) or ["users", "orders"]
            items = "".join(f"<li>{escape(name)}</li>" for name in names)
            note = f"<p>db user: app / {escape(self._tokens.get('db_password', ''))}</p>"
            return Reply(200, HTML, self._page("Database", f"<h1>Database</h1><ul>{items}</ul>{note}"),
                         touch="database page")
        return None

    def _table(self, name: str) -> Reply:
        columns = self._tables.get(name)
        if columns is None:
            return _json({"error": "not_found"}, 404)
        rng = random.Random(self._seed + name.encode("utf-8"))
        rows = [{column: self._data.value_for(rng, column, kind) for column, kind in columns}
                for _ in range(20)]
        return _json({"table": name, "columns": [{"name": c, "type": k} for c, k in columns],
                      "rows": rows}, touch=f"table {name[:40]}")

    def _page(self, title: str, content: str, head: str = "") -> bytes:
        name = escape(str(self._look["name"]))
        return (
            "<!doctype html>\n"
            '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{escape(title)} | {name}</title>\n{head}"
            '<link rel="icon" href="/assets/logo.svg" type="image/svg+xml">\n'
            '<link rel="stylesheet" href="/assets/site.css">\n</head>\n<body>\n'
            '<header><div class="wrap bar">'
            f'<a class="brand" href="/"><img src="/assets/logo.svg" alt="" width="28" height="28">{name}</a>'
            "</div></header>\n"
            f'<main><div class="wrap">{content}</div></main>\n'
            f'<footer><div class="wrap">&copy; {self._look["year"]} {name}</div></footer>\n'
            "</body>\n</html>\n"
        ).encode("utf-8")
