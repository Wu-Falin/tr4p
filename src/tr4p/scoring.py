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


def confidence(signals: Mapping[str, int], weights: Mapping[str, float]) -> float:
    """Combine signals into a 0-100 confidence value."""
    best: dict[str, float] = {}
    for name, count in signals.items():
        if count <= 0 or name not in GROUPS:
            continue
        repeats = min(count - 1, REPEAT_BONUS_CAP)
        value = weights.get(name, 0.0) * (1.0 + REPEAT_BONUS_STEP * repeats)
        group = GROUPS[name]
        if value > best.get(group, 0.0):
            best[group] = value
    return min(100.0, round(sum(best.values()), 1))


def tier_for(
    signals: Mapping[str, int],
    score: float,
    medium_threshold: float,
    trap_threshold: float,
    high_min_groups: int,
) -> str:
    """Map signals and score to a tier, enforcing the two-signal rule."""
    active = {name for name, count in signals.items() if count > 0}
    if not active:
        return TIER_NONE
    if "honeytoken" in active:
        return TIER_HIGH
    groups = evidence_groups(signals)
    if len(groups) < 2:
        return TIER_LOW
    if score >= trap_threshold:
        has_canary = bool(active & CANARY_TYPES)
        enough_groups = high_min_groups >= 2 and len(groups) >= high_min_groups
        if has_canary or enough_groups:
            return TIER_HIGH
    if score >= medium_threshold:
        return TIER_MEDIUM
    return TIER_LOW
