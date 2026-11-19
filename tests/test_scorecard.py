"""Detection scorecard: every scripted visitor must end in its expected tier.

Humans must stay at none, with no alerts. This is the guard rail for every
change to scoring, weights and signals."""

import pytest

from tests.profiles import PROFILES, TIERS, run_profile


@pytest.mark.parametrize("profile", PROFILES, ids=[p.name for p in PROFILES])
@pytest.mark.parametrize("seed", [1, 2, 3])
def test_profile_ends_in_its_expected_tier(profile, seed):
    tier, sink, engine = run_profile(profile, seed)
    assert TIERS.index(profile.lowest) <= TIERS.index(tier) <= TIERS.index(profile.highest), \
        f"{profile.name}: {tier}"
    if profile.highest == "none":
        assert tier == "none" and not [e for e in sink.events if e["alert"]], profile.name
        assert engine.stats()["tiers"] == {"low": 0, "medium": 0, "high": 0, "released": 0}


def test_every_expectation_is_stated():
    assert len({p.name for p in PROFILES}) == len(PROFILES) >= 12
    assert sum(p.highest == "none" for p in PROFILES) >= 4        # several kinds of ordinary visitor
