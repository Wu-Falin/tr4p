"""Tiring-level presets.

A level decides how hard confirmed sessions are hit: how long they wait, how
deep the fake file tree goes, how much text a long fake page holds, and how
often a high-tier request is sent into the maze. It deliberately does not
change how easily a session gets flagged: detection thresholds are separate
settings, so turning the level up never traps more people, it only costs the
already trapped ones more.
"""

from __future__ import annotations

from typing import Any

from tr4p.config import Config

# level -> config section -> values
PRESETS: dict[int, dict[str, dict[str, Any]]] = {
    1: {"tarpit": {"base_delay": 0.5, "max_delay": 4.0, "light_max_delay": 1.0},
        "maze": {"rabbit_depth": 2, "burn_bytes": 8192, "redirect_chance": 0.0}},
    2: {"tarpit": {"base_delay": 1.0, "max_delay": 8.0, "light_max_delay": 1.0},
        "maze": {"rabbit_depth": 3, "burn_bytes": 16384, "redirect_chance": 0.0}},
    3: {"tarpit": {"base_delay": 1.0, "max_delay": 16.0, "light_max_delay": 2.0},
        "maze": {"rabbit_depth": 4, "burn_bytes": 32768, "redirect_chance": 0.02}},
    4: {"tarpit": {"base_delay": 2.0, "max_delay": 32.0, "light_max_delay": 4.0},
        "maze": {"rabbit_depth": 6, "burn_bytes": 65536, "redirect_chance": 0.05}},
    5: {"tarpit": {"base_delay": 2.0, "max_delay": 60.0, "light_max_delay": 8.0},
        "maze": {"rabbit_depth": 8, "burn_bytes": 131072, "redirect_chance": 0.1}},
}
DEFAULT_LEVEL = 3
CUSTOM = 0


def preset_changes(level: int) -> dict[str, dict[str, Any]]:
    """Config changes that switch to a preset level."""
    if level not in PRESETS:
        raise ValueError("level must be 1-5")
    changes = {section: dict(values) for section, values in PRESETS[level].items()}
    changes["tarpit"]["level"] = level
    return changes


def level_of(config: Config) -> int:
    """The preset the current values correspond to, or 0 for custom."""
    for level, sections in PRESETS.items():
        if all(
            abs(getattr(getattr(config, section), name) - value) < 1e-9
            for section, values in sections.items()
            for name, value in values.items()
        ):
            return level
    return CUSTOM
