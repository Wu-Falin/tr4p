"""Confidence scoring and tiers.

Rules, in plain words:

* Every signal type has a weight on a 0-100 scale.
* Signal types that stem from the same underlying behaviour share an
  evidence group. A group contributes its strongest signal once, so related
  observations cannot stack into false certainty.
* One group alone never does more than log, whatever its score.
* The high tier additionally needs a canary-type signal, or several
  independent groups agreeing.
* A honeytoken coming back is the single exception: nobody can hold one
  without having read hidden bait first, so it is sufficient by itself.
* Evidence a session merely inherited, because it shares an address and
  header fingerprint with a trapped one, counts at reduced weight and can
  never produce the high tier without the session's own signals.
"""

from __future__ import annotations

from typing import Mapping

TIER_NONE = "none"
TIER_LOW = "low"
TIER_MEDIUM = "medium"
TIER_HIGH = "high"
TIERS = (TIER_NONE, TIER_LOW, TIER_MEDIUM, TIER_HIGH)
TIER_RANK = {name: rank for rank, name in enumerate(TIERS)}

# signal type -> evidence group
GROUPS: dict[str, str] = {
    "canary_path": "hidden_path",
    "robots_violation": "hidden_path",
    "hidden_instruction": "instruction",
    "probe_path": "probe",
    "attack_payload": "payload",
    "scanner_ua": "client",
    "generic_client": "client",
    "header_anomaly": "client",
    "rate": "volume",
    "not_found_burst": "volume",
    "auth_burst": "volume",
    "no_assets": "fetch_pattern",
    "honeytoken": "honeytoken",
}

# Signals that mean "touched something only the trap advertises".
CANARY_TYPES = frozenset(
    {"canary_path", "robots_violation", "hidden_instruction", "probe_path", "honeytoken"}
)

REPEAT_BONUS_STEP = 0.125
REPEAT_BONUS_CAP = 4


def evidence_groups(signals: Mapping[str, int]) -> set[str]:
    return {GROUPS[name] for name, count in signals.items() if count > 0 and name in GROUPS}


def _group_values(signals: Mapping[str, int], weights: Mapping[str, float], factor: float) -> dict[str, float]:
    """Strongest signal per evidence group, with the repeat bonus applied."""
    best: dict[str, float] = {}
    for name, count in signals.items():
        if count <= 0 or name not in GROUPS:
            continue
        repeats = min(count - 1, REPEAT_BONUS_CAP)
        value = weights.get(name, 0.0) * (1.0 + REPEAT_BONUS_STEP * repeats) * factor
        group = GROUPS[name]
        if value > best.get(group, 0.0):
            best[group] = value
    return best


def confidence(
    signals: Mapping[str, int],
    weights: Mapping[str, float],
    inherited: Mapping[str, int] | None = None,
    inherited_weight: float = 1.0,
) -> float:
    """Combine signals into a 0-100 confidence value."""
    best = _group_values(signals, weights, 1.0)
    if inherited:
        for group, value in _group_values(inherited, weights, inherited_weight).items():
            if value > best.get(group, 0.0):
                best[group] = value
    return min(100.0, round(sum(best.values()), 1))


def tier_for(
    signals: Mapping[str, int],
    score: float,
    medium_threshold: float,
    trap_threshold: float,
    high_min_groups: int,
    inherited: Mapping[str, int] | None = None,
) -> str:
    """Map signals and score to a tier, enforcing the two-signal rule."""
    own = {name for name, count in signals.items() if count > 0}
    carried = {name for name, count in (inherited or {}).items() if count > 0}
    active = own | carried
    if not active:
        return TIER_NONE
    if "honeytoken" in own:
        return TIER_HIGH
    groups = {GROUPS[name] for name in active if name in GROUPS}
    # An inherited honeytoken still stands on its own as evidence; it is
    # only barred from reaching the high tier (the `own` check below).
    if len(groups) < 2 and "honeytoken" not in carried:
        return TIER_LOW
    if score >= trap_threshold:
        # What qualifies a session for the high tier must be its own doing.
        own_groups = {GROUPS[name] for name in own if name in GROUPS}
        has_canary = bool(own & CANARY_TYPES)
        enough_groups = high_min_groups >= 2 and len(own_groups) >= high_min_groups
        if has_canary or enough_groups:
            return TIER_HIGH
    if score >= medium_threshold:
        return TIER_MEDIUM
    return TIER_LOW
