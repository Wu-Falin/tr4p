"""Optional schema import for the decoy.

Reads table names, column names and column types from a SQL schema file so
the decoy's fake database has the same shape as the defender's. Values are
never read: a file that contains data rows is refused outright.

The file is untrusted input. It is size-capped, scanned with a small
tokenizer and never executed or handed to a database.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from tr4p.fsutil import write_private

SCHEMA_FILE = "decoy-schema.json"
MAX_BYTES = 1024 * 1024
MAX_TABLES = 200
MAX_COLUMNS = 200

_IDENT = r"[A-Za-z_][A-Za-z0-9_]{0,62}"
_DATA = re.compile(r"\b(?:insert\s+into|copy\s+\S+.*?\bfrom\s+stdin|load\s+data|values\s*\()",
                   re.IGNORECASE | re.DOTALL)
_COMMENTS = re.compile(r"--[^\n]*|/\*.*?\*/", re.DOTALL)
_CREATE = re.compile(
    rf"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:[`\"\[]?{_IDENT}[`\"\]]?\.)?[`\"\[]?({_IDENT})[`\"\]]?\s*\(",
    re.IGNORECASE)
_COLUMN = re.compile(rf"^[`\"\[]?({_IDENT})[`\"\]]?\s+([A-Za-z][A-Za-z0-9_ ]{{0,30}}?)(?:\s*\(|\s|,|$)")
_NOT_COLUMNS = frozenset({"primary", "foreign", "unique", "constraint", "key", "index", "check",
                          "fulltext", "spatial", "like", "exclude", "period"})


class SchemaError(ValueError):
    """The schema file was refused."""


def parse_schema(text: str) -> dict:
    """Return {"tables": [{"name", "columns": [{"name", "type"}]}]}."""
    if len(text.encode("utf-8", "replace")) > MAX_BYTES:
        raise SchemaError("schema file is larger than 1 MiB")
    if "\x00" in text:
        raise SchemaError("schema file is not text")
    text = _COMMENTS.sub(" ", text)
    if _DATA.search(text):
        raise SchemaError("the file contains data rows; export the schema only "
                          "(for example mysqldump --no-data or pg_dump --schema-only)")
    tables = []
    for match in _CREATE.finditer(text):
        body = _balanced(text, match.end())
        columns = []
        for part in _split_top_level(body):
            found = _COLUMN.match(part.strip())
            if not found or found.group(1).lower() in _NOT_COLUMNS:
                continue
            columns.append({"name": found.group(1), "type": found.group(2).strip().lower()[:30]})
            if len(columns) >= MAX_COLUMNS:
                break
        if columns:
            tables.append({"name": match.group(1), "columns": columns})
        if len(tables) >= MAX_TABLES:
            break
    if not tables:
        raise SchemaError("no CREATE TABLE statements found")
    return {"tables": tables}


def _balanced(text: str, start: int) -> str:
    """Text inside the parentheses opened just before `start`."""
    depth, index = 1, start
    while index < len(text) and depth:
        char = text[index]
        depth += (char == "(") - (char == ")")
        index += 1
    return text[start:index - 1]


def _split_top_level(body: str) -> list[str]:
    parts, depth, current = [], 0, []
    for char in body:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def import_schema(source: Path, home: Path) -> dict:
    if source.stat().st_size > MAX_BYTES:
        raise SchemaError("schema file is larger than 1 MiB")
    schema = parse_schema(source.read_text(encoding="utf-8", errors="replace"))
    write_private(home / SCHEMA_FILE, json.dumps(schema, indent=1).encode("utf-8"))
    return schema


def load_schema(home: Path) -> dict | None:
    path = home / SCHEMA_FILE
    if not path.is_file() or path.stat().st_size > 4 * MAX_BYTES:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    return data if isinstance(data, dict) else None
