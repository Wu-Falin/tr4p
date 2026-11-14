"""Configuration model.

The config is a single JSON file in the home directory. It is written by the
init wizard and by the dashboard, so it is machine-friendly; every value has a
safe default and is validated on load.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from tr4p.fsutil import write_private

CONFIG_FILE = "config.json"
SEED_FILE = "secret.key"
DATABASE_FILE = "events.db"

MODES = ("proxy", "standalone")
COOKIE_MODES = ("always", "on_signal")
DECOY_PROFILES = ("generic", "php", "wordpress", "api")

# Default weight of each signal type on the 0-100 confidence scale.
DEFAULT_WEIGHTS: dict[str, float] = {
    "honeytoken": 100.0,
    "hidden_instruction": 50.0,
    "canary_path": 45.0,
    "robots_violation": 40.0,
    "probe_path": 35.0,
    "attack_payload": 35.0,
    "scanner_ua": 30.0,
    "not_found_burst": 30.0,
    "auth_burst": 30.0,
    "rate": 25.0,
    "no_assets": 15.0,
    "header_anomaly": 15.0,
    "generic_client": 10.0,
}


class ConfigError(ValueError):
    """Raised when the config file is missing, malformed or unsafe."""


@dataclass
class PublicConfig:
    """The listener attackers and real users talk to."""

    mode: str = "proxy"
    host: str = "0.0.0.0"
    port: int = 8080
    upstream: str = "http://127.0.0.1:3000"
    preserve_host: bool = True
    upstream_timeout: float = 30.0
    upstream_connections: int = 64
    max_body_bytes: int = 32 * 1024 * 1024
    # Peers allowed to tell us the real client address (your TLS proxy or CDN).
    trusted_proxies: list[str] = field(default_factory=list)
    client_ip_header: str = "X-Forwarded-For"
    # Self-protection. Connections beyond the cap are refused, after first
    # trying to free a slot by dropping the oldest tarpitted connection.
    max_connections: int = 4096
    # A connection with no request in progress is closed after this long.
    idle_timeout: float = 20.0
    # An upload that stalls for this long is abandoned.
    body_timeout: float = 30.0


@dataclass
class DashboardConfig:
    """Local admin interface. Keep it on loopback unless you know why not."""

    host: str = "127.0.0.1"
    port: int = 8787
    # Extra Host header values to accept (for example a tunnel hostname).
    allowed_hosts: list[str] = field(default_factory=list)
    session_hours: float = 12.0


@dataclass
class DetectionConfig:
    medium_threshold: float = 40.0
    trap_threshold: float = 70.0
    # Without a canary-type signal, this many independent evidence groups are
    # needed to reach the high tier. 0 disables that path entirely.
    high_min_groups: int = 3
    weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    rate_window: float = 10.0
    rate_max_requests: int = 40
    not_found_window: float = 60.0
    not_found_max: int = 15
    auth_window: float = 60.0
    auth_max: int = 10
    no_assets_min_pages: int = 8
    inspect_body_bytes: int = 8192
    verify_crawlers: bool = True
    extra_scanner_agents: list[str] = field(default_factory=list)
    # Evidence that reaches a session only because it shares an address and
    # header fingerprint with a trapped one counts for this fraction, and can
    # never lift the session above the medium tier by itself.
    inherited_weight: float = 0.7


@dataclass
class CanaryConfig:
    rotation_hours: float = 24.0
    # Rotated-out canaries stay armed this many rotations: a link harvested
    # last week is still something no human visits.
    keep_rotations: int = 7
    links_per_page: int = 2


@dataclass
class InjectConfig:
    enabled: bool = True
    max_body_bytes: int = 1024 * 1024


@dataclass
class SessionConfig:
    cookie_mode: str = "always"
    max_tracked: int = 20000
    idle_seconds: float = 1800.0
    flagged_days: float = 7.0
    # A flagged session with no new signal for this long starts over.
    trap_ttl_hours: float = 24.0
    # Evidence inherited by fingerprint alone is forgotten much sooner.
    inherited_ttl_minutes: float = 30.0


@dataclass
class TarpitConfig:
    """Escalating delays for sessions in the medium and high tiers."""

    enabled: bool = True
    # 1-5 selects a preset for the three delay values below; 0 means custom.
    level: int = 3
    base_delay: float = 1.0
    max_delay: float = 16.0
    # Medium-tier sessions never wait longer than this ("light" tarpit).
    light_max_delay: float = 2.0
    # The delay doubles after this many delayed requests.
    phase_requests: int = 2
    jitter: float = 0.15
    # While a response is held back, a piece of it is sent this often so the
    # client's read timeout never fires.
    drip_interval: float = 2.0
    # Clients that pile up parallel requests or abandon delayed ones move
    # through the phases faster. Only ever applies to already trapped sessions.
    adaptive: bool = True
    # Self-protection: sessions held at once (oldest is dropped beyond this),
    # requests per held session, and memory spent on held responses.
    max_sessions: int = 2000
    session_concurrency: int = 2
    session_queue: int = 6
    buffer_bytes: int = 256 * 1024
    buffer_total_bytes: int = 48 * 1024 * 1024


@dataclass
class MazeConfig:
    """Rabbit hole, token-burn pages and teleport. Canary territory only."""

    # How many directory levels the fake file tree goes down.
    rabbit_depth: int = 4
    # Size of a long fake page for a trapped session (hard cap 512 KiB).
    burn_bytes: int = 32768
    # Chance that a high-tier request is redirected into the maze.
    redirect_chance: float = 0.02
    redirect_min_phase: int = 2
    # Optional outside targets. Empty means the built-in maze is used.
    external_targets: list[str] = field(default_factory=list)
    # Vary request ids, ordering and formatting between answers.
    mutate: bool = True


@dataclass
class AlertConfig:
    min_tier: str = "high"
    webhook_url: str = ""
    # Webhooks to private or loopback addresses are refused unless this is set.
    webhook_allow_private: bool = False
    webhook_timeout: float = 5.0
    email_to: list[str] = field(default_factory=list)
    email_from: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_security: str = "starttls"
    rate_per_minute: int = 6
    dedupe_minutes: float = 10.0


@dataclass
class BlockConfig:
    """Address-and-fingerprint entries for high-tier sessions."""

    # Refuse listed clients outright. Off by default: holding them in the
    # tarpit costs them more and tells them less.
    enforce: bool = False
    # Keep blocklist.txt in the home directory for other tools to read.
    export: bool = True
    ttl_hours: float = 24.0
    max_entries: int = 5000


@dataclass
class DecoyConfig:
    """Emulated application that high-tier sessions are quietly moved to."""

    enabled: bool = True
    # generic, php, wordpress or api
    profile: str = "generic"
    timeout: float = 5.0
    # Container setups run the decoy as its own service. Set its address
    # here and the directory both services share for the hand-over file.
    # Empty means: start the decoy as a local child process.
    url: str = ""
    handoff_dir: str = ""


@dataclass
class StorageConfig:
    max_events: int = 200000
    # Events and flagged sessions older than this are deleted. Client
    # addresses can be personal data: keep them only as long as needed.
    retention_days: float = 30.0


@dataclass
class Config:
    version: int = 1
    instance_name: str = "default"
    public: PublicConfig = field(default_factory=PublicConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    canary: CanaryConfig = field(default_factory=CanaryConfig)
    inject: InjectConfig = field(default_factory=InjectConfig)
    session: SessionConfig = field(default_factory=SessionConfig)
    tarpit: TarpitConfig = field(default_factory=TarpitConfig)
    maze: MazeConfig = field(default_factory=MazeConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    block: BlockConfig = field(default_factory=BlockConfig)
    decoy: DecoyConfig = field(default_factory=DecoyConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    # Addresses or networks that bypass detection (your own pentest hosts).
    whitelist: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        config = _build(cls, data, "config")
        config.validate()
        return config

    @classmethod
    def load(cls, path: Path) -> "Config":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ConfigError(f"no config at {path}; run `tr4p init` first") from exc
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{path.name} is not valid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"{path.name} must contain a JSON object")
        return cls.from_dict(raw)

    def apply(self, changes: dict[str, Any]) -> None:
        """Apply a partial update in place, or raise ConfigError and change
        nothing. Running components keep their references to the section
        objects, so the new values take effect immediately."""
        merged = self.to_dict()
        for section, values in changes.items():
            if isinstance(merged.get(section), dict) and isinstance(values, dict):
                merged[section].update(values)
            else:
                merged[section] = values
        candidate = Config.from_dict(merged)
        for item in dataclasses.fields(self):
            current, fresh = getattr(self, item.name), getattr(candidate, item.name)
            if dataclasses.is_dataclass(current):
                for inner in dataclasses.fields(current):
                    setattr(current, inner.name, getattr(fresh, inner.name))
            else:
                setattr(self, item.name, fresh)

    def save(self, path: Path) -> None:
        self.validate()
        text = json.dumps(self.to_dict(), indent=2, sort_keys=False) + "\n"
        write_private(path, text.encode("utf-8"))

    def validate(self) -> None:
        public, dash, det = self.public, self.dashboard, self.detection
        _require(public.mode in MODES, f"public.mode must be one of {MODES}")
        if public.mode == "proxy":
            parts = urlsplit(public.upstream)
            _require(
                parts.scheme in ("http", "https") and bool(parts.netloc),
                "public.upstream must be an http(s) URL such as http://127.0.0.1:3000",
            )
        for name, port in (("public.port", public.port), ("dashboard.port", dash.port)):
            _require(1 <= port <= 65535, f"{name} must be between 1 and 65535")
        _require(
            public.port != dash.port,
            "dashboard.port must differ from public.port",
        )
        _require(public.upstream_timeout > 0, "public.upstream_timeout must be positive")
        _require(public.upstream_connections >= 1, "public.upstream_connections must be >= 1")
        _require(public.max_body_bytes >= 0, "public.max_body_bytes must be >= 0")
        _require(
            0 < det.medium_threshold <= det.trap_threshold <= 100,
            "detection thresholds must satisfy 0 < medium <= trap <= 100",
        )
        _require(det.high_min_groups == 0 or det.high_min_groups >= 2,
                 "detection.high_min_groups must be 0 (off) or at least 2")
        unknown = set(det.weights) - set(DEFAULT_WEIGHTS)
        _require(not unknown, f"unknown signal weights: {sorted(unknown)}")
        for key, value in DEFAULT_WEIGHTS.items():
            det.weights.setdefault(key, value)
        for key, value in det.weights.items():
            _require(0 <= value <= 100, f"detection.weights.{key} must be within 0-100")
        for name in ("rate_window", "not_found_window", "auth_window"):
            _require(getattr(det, name) > 0, f"detection.{name} must be positive")
        for name in ("rate_max_requests", "not_found_max", "auth_max", "no_assets_min_pages"):
            _require(getattr(det, name) >= 1, f"detection.{name} must be >= 1")
        _require(det.inspect_body_bytes >= 0, "detection.inspect_body_bytes must be >= 0")
        _require(self.canary.rotation_hours > 0, "canary.rotation_hours must be positive")
        _require(self.canary.keep_rotations >= 1, "canary.keep_rotations must be >= 1")
        _require(0 <= self.canary.links_per_page <= 8, "canary.links_per_page must be 0-8")
        _require(self.inject.max_body_bytes >= 0, "inject.max_body_bytes must be >= 0")
        _require(
            self.session.cookie_mode in COOKIE_MODES,
            f"session.cookie_mode must be one of {COOKIE_MODES}",
        )
        _require(self.session.max_tracked >= 100, "session.max_tracked must be >= 100")
        _require(self.session.idle_seconds > 0, "session.idle_seconds must be positive")
        _require(self.session.flagged_days > 0, "session.flagged_days must be positive")
        _require(self.session.trap_ttl_hours > 0, "session.trap_ttl_hours must be positive")
        _require(self.session.inherited_ttl_minutes > 0,
                 "session.inherited_ttl_minutes must be positive")
        _require(0 <= det.inherited_weight <= 1, "detection.inherited_weight must be 0-1")
        _require(public.max_connections >= 16, "public.max_connections must be >= 16")
        _require(public.idle_timeout >= 1, "public.idle_timeout must be >= 1")
        _require(public.body_timeout >= 1, "public.body_timeout must be >= 1")
        pit = self.tarpit
        _require(0 <= pit.level <= 5, "tarpit.level must be 0 (custom) or 1-5")
        _require(0.1 <= pit.base_delay <= 60, "tarpit.base_delay must be 0.1-60 seconds")
        _require(pit.base_delay <= pit.max_delay <= 300,
                 "tarpit.max_delay must be between base_delay and 300 seconds")
        _require(0 < pit.light_max_delay <= pit.max_delay,
                 "tarpit.light_max_delay must be positive and at most max_delay")
        _require(pit.phase_requests >= 1, "tarpit.phase_requests must be >= 1")
        _require(0 <= pit.jitter <= 0.5, "tarpit.jitter must be 0-0.5")
        _require(pit.drip_interval >= 0.2, "tarpit.drip_interval must be >= 0.2")
        _require(10 <= pit.max_sessions <= 100000, "tarpit.max_sessions must be 10-100000")
        _require(1 <= pit.session_concurrency <= 16, "tarpit.session_concurrency must be 1-16")
        _require(0 <= pit.session_queue <= 64, "tarpit.session_queue must be 0-64")
        _require(pit.buffer_bytes >= 0, "tarpit.buffer_bytes must be >= 0")
        _require(pit.buffer_total_bytes >= 0, "tarpit.buffer_total_bytes must be >= 0")
        maze, alerts, block = self.maze, self.alerts, self.block
        _require(1 <= maze.rabbit_depth <= 12, "maze.rabbit_depth must be 1-12")
        _require(1024 <= maze.burn_bytes <= 512 * 1024, "maze.burn_bytes must be 1024-524288")
        _require(0 <= maze.redirect_chance <= 1, "maze.redirect_chance must be 0-1")
        _require(0 <= maze.redirect_min_phase <= 40, "maze.redirect_min_phase must be 0-40")
        for target in maze.external_targets:
            _require(_is_http_url(target), f"maze.external_targets: {target!r} is not an http(s) URL")
        _require(alerts.min_tier in ("medium", "high"), "alerts.min_tier must be medium or high")
        _require(not alerts.webhook_url or _is_http_url(alerts.webhook_url),
                 "alerts.webhook_url must be an http(s) URL")
        _require(1 <= alerts.webhook_timeout <= 30, "alerts.webhook_timeout must be 1-30 seconds")
        _require(alerts.smtp_security in ("starttls", "ssl", "none"),
                 "alerts.smtp_security must be starttls, ssl or none")
        _require(1 <= alerts.smtp_port <= 65535, "alerts.smtp_port must be 1-65535")
        _require(all("@" in item and " " not in item for item in alerts.email_to),
                 "alerts.email_to must be a list of e-mail addresses")
        _require(1 <= alerts.rate_per_minute <= 60, "alerts.rate_per_minute must be 1-60")
        _require(alerts.dedupe_minutes >= 0, "alerts.dedupe_minutes must be >= 0")
        _require(block.ttl_hours > 0, "block.ttl_hours must be positive")
        _require(10 <= block.max_entries <= 100000, "block.max_entries must be 10-100000")
        _require(self.decoy.profile in DECOY_PROFILES,
                 f"decoy.profile must be one of {DECOY_PROFILES}")
        _require(1 <= self.decoy.timeout <= 30, "decoy.timeout must be 1-30 seconds")
        _require(not self.decoy.url or _is_http_url(self.decoy.url),
                 "decoy.url must be an http(s) URL")
        _require(not self.decoy.url or bool(self.decoy.handoff_dir),
                 "decoy.handoff_dir is required when decoy.url is set")
        _require(self.storage.retention_days > 0, "storage.retention_days must be positive")
        _require(self.storage.max_events >= 1000, "storage.max_events must be >= 1000")
        _require(dash.session_hours > 0, "dashboard.session_hours must be positive")
        parse_networks(self.whitelist, "whitelist")
        parse_networks(public.trusted_proxies, "public.trusted_proxies")


def parse_networks(entries: list[str], name: str) -> list[ipaddress._BaseNetwork]:
    """Turn address or CIDR strings into network objects, failing loudly."""
    networks = []
    for entry in entries:
        try:
            networks.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError as exc:
            raise ConfigError(f"{name}: {entry!r} is not an IP address or network") from exc
    return networks


def _is_http_url(value: str) -> bool:
    parts = urlsplit(value)
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigError(message)


def _build(cls: type, data: Any, where: str) -> Any:
    """Build a dataclass from plain JSON data with basic type checking."""
    if not isinstance(data, dict):
        raise ConfigError(f"{where} must be an object")
    known = {item.name: item for item in dataclasses.fields(cls)}
    unknown = set(data) - set(known)
    if unknown:
        raise ConfigError(f"{where}: unknown setting(s) {sorted(unknown)}")
    instance = cls()
    for name, value in data.items():
        current = getattr(instance, name)
        label = f"{where}.{name}"
        if dataclasses.is_dataclass(current):
            value = _build(type(current), value, label)
        elif isinstance(current, bool):
            _require(isinstance(value, bool), f"{label} must be true or false")
        elif isinstance(current, int):
            _require(isinstance(value, int) and not isinstance(value, bool),
                     f"{label} must be a whole number")
        elif isinstance(current, float):
            _require(isinstance(value, (int, float)) and not isinstance(value, bool),
                     f"{label} must be a number")
            value = float(value)
        elif isinstance(current, str):
            _require(isinstance(value, str), f"{label} must be text")
        elif isinstance(current, list):
            _require(isinstance(value, list) and all(isinstance(v, str) for v in value),
                     f"{label} must be a list of text values")
            value = list(value)
        elif isinstance(current, dict):
            _require(
                isinstance(value, dict)
                and all(isinstance(v, (int, float)) and not isinstance(v, bool)
                        for v in value.values()),
                f"{label} must map names to numbers",
            )
            value = {str(k): float(v) for k, v in value.items()}
        setattr(instance, name, value)
    return instance
