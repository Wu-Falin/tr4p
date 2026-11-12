"""Tiring-level presets.

A level decides how hard confirmed sessions are hit. It deliberately does not
change how easily a session gets flagged: detection thresholds are separate
settings, so turning the level up never traps more people, it only costs the
already trapped ones more time.
"""

from __future__ import annotations

from tr4p.config import Config

# level -> tarpit values
PRESETS: dict[int, dict[str, float]] = {
    1: {"base_delay": 0.5, "max_delay": 4.0, "light_max_delay": 1.0},
    2: {"base_delay": 1.0, "max_delay": 8.0, "light_max_delay": 1.0},
    3: {"base_delay": 1.0, "max_delay": 16.0, "light_max_delay": 2.0},
    4: {"base_delay": 2.0, "max_delay": 32.0, "light_max_delay": 4.0},
    5: {"base_delay": 2.0, "max_delay": 60.0, "light_max_delay": 8.0},
}
DEFAULT_LEVEL = 3
CUSTOM = 0


def preset_changes(level: int) -> dict[str, dict[str, float]]:
    """Config changes that switch to a preset level."""
    if level not in PRESETS:
        raise ValueError("level must be 1-5")
    return {"tarpit": {"level": level, **PRESETS[level]}}


def level_of(config: Config) -> int:
    """The preset the current values correspond to, or 0 for custom."""
    pit = config.tarpit
    for level, values in PRESETS.items():
        if all(abs(getattr(pit, name) - value) < 1e-9 for name, value in values.items()):
            return level
    return CUSTOM
