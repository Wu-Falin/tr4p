"""Incident reports for one session.

Everything an attacker controls (paths, user agents, detail text) is
untrusted. Before it goes into a report it loses control characters and
direction overrides, is shortened, and for Markdown is also escaped, so a
report can be opened in a viewer that renders Markdown or the HTML inside it
without anything coming alive.

Measured figures (requests, held seconds, bytes sent) are reported as such.
The token figure is an estimate and says so.
"""

from __future__ import annotations

import json
import time
from typing import Any

STAGES = (
    ("Reconnaissance", ("robots_violation", "canary_path", "hidden_instruction")),
    ("Mapping", ("follow_through", "enumeration")),
    ("Probing", ("probe_path", "attack_payload", "scanner_ua", "not_found_burst", "retry_pattern")),
    ("Access attempts", ("honeytoken", "tamper", "auth_burst")),
    ("Automation traits", ("generic_client", "header_anomaly", "rate", "no_assets", "cadence",
                           "concurrency")),
)
ESTIMATE_NOTE = ("Estimate: bytes of trap content sent to this session divided by 4, as a rough "
                 "count of input tokens. No price is assumed.")
PRIVACY_NOTE = ("This report contains a client address. Treat it as personal data and keep it only "
                "as long as needed.")
TIMELINE_LIMIT = 200
_MARKDOWN_SPECIALS = "\\`*_{}[]()#+-.!|~"


def clean_text(value: object, limit: int = 200) -> str:
    """No control characters, direction overrides or line breaks; bounded."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(value))[:limit]


def md_escape(value: object, limit: int = 200) -> str:
    """Safe to place in Markdown, including Markdown that is rendered as HTML."""
    text = clean_text(value, limit).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("@", "&#64;")
    return "".join("\\" + ch if ch in _MARKDOWN_SPECIALS else ch for ch in text)


def _iso(stamp: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp)) if stamp else ""


def build_report(session: dict[str, Any], events: list[dict[str, Any]], now: float) -> dict[str, Any]:
    """`events` oldest first. Every string in the result is already cleaned."""
    signals = {str(k): int(v) for k, v in dict(session.get("signals", {})).items() if int(v) > 0}
    first: dict[str, dict[str, Any]] = {}
    touches = []
    for event in events:
        if event.get("kind") == "signal" and event.get("signal") not in first:
            first[str(event["signal"])] = event
        if event.get("signal") == "decoy_touch":
            touches.append(clean_text(event.get("detail", ""), 120))
    stages = []
    for name, types in STAGES:
        present = {t: signals[t] for t in types if t in signals}
        if not present:
            continue
        starts = [first[t] for t in present if t in first]
        earliest = min(starts, key=lambda e: e["ts"]) if starts else None
        stages.append({"stage": name, "signals": present,
                       "first": _iso(earliest["ts"]) if earliest else "",
                       "example": clean_text(earliest.get("detail", ""), 160) if earliest else ""})
    if touches:
        stages.append({"stage": "Decoy interaction", "signals": {"decoy_touch": len(touches)},
                       "first": "", "example": "; ".join(touches[:3])})
    served = int(session.get("served_bytes", 0))
    return {
        "version": 1,
        "generated": _iso(now),
        "session": {
            "id": clean_text(session.get("key", ""), 40),
            "address": clean_text(session.get("ip", ""), 64),
            "user_agent": clean_text(session.get("user_agent", ""), 160),
            "tier": clean_text(session.get("tier", ""), 12),
            "score": round(float(session.get("score", 0.0))),
            "phase": int(session.get("phase", 0)),
            "campaign": clean_text(session.get("campaign", ""), 20),
            "decoy_theme": clean_text(session.get("theme", ""), 20),
            "first_seen": _iso(float(session.get("created", 0.0))),
            "last_seen": _iso(float(session.get("last_seen", 0.0))),
        },
        "metrics": {
            "requests": int(session.get("requests", 0)),
            "held_seconds": round(float(session.get("held_seconds", 0.0)), 1),
            "bytes_sent": served,
            "estimated_tokens": served // 4,
        },
        "stages": stages,
        "timeline": [
            {"time": _iso(float(e.get("ts", 0.0))), "kind": clean_text(e.get("kind", ""), 20),
             "signal": clean_text(e.get("signal", ""), 30), "tier": clean_text(e.get("tier", ""), 12),
             "detail": clean_text(e.get("detail", ""), 200),
             "request": clean_text(f"{e.get('method', '')} {e.get('path', '')}".strip(), 200)}
            for e in events[-TIMELINE_LIMIT:]
        ],
        "notes": [ESTIMATE_NOTE, PRIVACY_NOTE],
    }


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=True) + "\n"


def to_markdown(report: dict[str, Any]) -> str:
    s, m = report["session"], report["metrics"]
    e = md_escape
    lines = [
        f"# Incident report: session {e(s['id'])}", "",
        f"Generated {e(report['generated'])}.", "",
        "## Summary", "",
        f"- Address: {e(s['address'])}",
        f"- Client: {e(s['user_agent'])}",
        f"- Tier: {e(s['tier'])} (score {s['score']}, tarpit phase {s['phase']})",
        f"- Seen: {e(s['first_seen'])} to {e(s['last_seen'])}",
    ]
    if s["campaign"]:
        lines.append(f"- Campaign: {e(s['campaign'])} (linked to other sessions by a reused secret)")
    if s["decoy_theme"]:
        lines.append(f"- Decoy presented: {e(s['decoy_theme'])}")
    lines += ["", "## Cost to the attacker", "",
              f"- Requests: {m['requests']}",
              f"- Time answers were held back: {m['held_seconds']} s (measured)",
              f"- Trap content sent: {m['bytes_sent']} bytes (measured)",
              f"- Estimated tokens: about {m['estimated_tokens']} (estimate)", "",
              "## What it did", ""]
    if not report["stages"]:
        lines.append("No stages recorded.")
    for stage in report["stages"]:
        counts = ", ".join(f"{e(name)} x{count}" for name, count in sorted(stage["signals"].items()))
        lines.append(f"- {stage['stage']}: {counts}")
        if stage["example"]:
            lines.append(f"  - for example: {e(stage['example'])}")
    lines += ["", "## Timeline", ""]
    for item in report["timeline"]:
        what = item["signal"] or item["kind"]
        request = f" ({e(item['request'])})" if item["request"] else ""
        lines.append(f"- {e(item['time'])} {e(item['tier'])} {e(what)}: {e(item['detail'])}{request}")
    if not report["timeline"]:
        lines.append("No events recorded.")
    lines += ["", "## Notes", ""] + [f"- {e(note, 300)}" for note in report["notes"]]
    return "\n".join(lines) + "\n"
