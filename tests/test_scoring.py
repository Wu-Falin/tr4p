from tr4p.config import DEFAULT_WEIGHTS
from tr4p.scoring import GROUPS, confidence, evidence_groups, tier_for


def tier(signals, medium=40.0, trap=70.0, groups=3):
    return tier_for(signals, confidence(signals, DEFAULT_WEIGHTS), medium, trap, groups)


def test_every_weighted_signal_has_a_group():
    assert set(GROUPS) == set(DEFAULT_WEIGHTS)


def test_no_signals_is_none():
    assert tier({}) == "none"
    assert confidence({}, DEFAULT_WEIGHTS) == 0.0


def test_single_signal_only_logs_whatever_its_count():
    for name in DEFAULT_WEIGHTS:
        if name == "honeytoken":
            continue
        assert tier({name: 1}) == "low", name
        assert tier({name: 500}) == "low", name


def test_related_signals_do_not_stack():
    # Three volume signals are one piece of evidence, not three.
    volume = {"rate": 3, "not_found_burst": 3, "auth_burst": 3}
    assert evidence_groups(volume) == {"volume"}
    assert tier(volume) == "low"
    # Two ways of touching hidden paths are one piece of evidence as well.
    assert tier({"canary_path": 9, "robots_violation": 9}) == "low"
    assert confidence(volume, DEFAULT_WEIGHTS) == confidence({"auth_burst": 3}, DEFAULT_WEIGHTS)


def test_two_groups_reach_medium_then_high_with_a_canary():
    assert tier({"probe_path": 1, "generic_client": 1}) == "medium"
    assert tier({"canary_path": 1, "generic_client": 1}) == "medium"
    assert tier({"canary_path": 1, "rate": 1}) == "high"
    assert tier({"hidden_instruction": 1, "generic_client": 1, "no_assets": 1}) == "high"


def test_two_weak_groups_stay_low():
    assert tier({"header_anomaly": 1, "no_assets": 1}) == "low"


def test_high_without_canary_needs_three_groups():
    two = {"scanner_ua": 1, "attack_payload": 5}
    assert confidence(two, DEFAULT_WEIGHTS) >= 70
    assert tier(two) == "medium"
    assert tier({**two, "rate": 1}) == "high"
    assert tier({**two, "rate": 1}, groups=0) == "medium"


def test_honeytoken_is_sufficient_alone():
    assert tier({"honeytoken": 1}) == "high"
    assert confidence({"honeytoken": 1}, DEFAULT_WEIGHTS) == 100.0


def test_repeat_bonus_is_capped():
    weights = {"canary_path": 40.0}
    assert confidence({"canary_path": 1}, weights) == 40.0
    assert confidence({"canary_path": 5}, weights) == 60.0
    assert confidence({"canary_path": 5000}, weights) == 60.0


def test_score_never_exceeds_100():
    everything = {name: 10 for name in DEFAULT_WEIGHTS}
    assert confidence(everything, DEFAULT_WEIGHTS) == 100.0


def test_thresholds_are_respected():
    signals = {"canary_path": 1, "generic_client": 1}  # 55
    assert tier(signals, medium=60, trap=90) == "low"
    assert tier(signals, medium=40, trap=50) == "high"


def inherited_tier(own, inherited, weight=0.7):
    score = confidence(own, DEFAULT_WEIGHTS, inherited, weight)
    return tier_for(own, score, 40.0, 70.0, 3, inherited), score


def test_inherited_evidence_is_discounted_per_group():
    _, score = inherited_tier({}, {"canary_path": 1, "rate": 1})
    assert score == 49.0                                   # (45 + 25) * 0.7
    _, score = inherited_tier({"canary_path": 1}, {"canary_path": 1, "rate": 1})
    assert score == 62.5                                   # own 45 beats inherited 31.5


def test_inherited_evidence_alone_never_reaches_high():
    everything = {name: 9 for name in DEFAULT_WEIGHTS}
    tier, score = inherited_tier({}, everything, weight=1.0)
    assert score == 100.0 and tier == "medium"
    assert inherited_tier({}, {"honeytoken": 1})[0] == "medium"
    assert inherited_tier({}, {"canary_path": 1})[0] == "low"


def test_a_weak_own_signal_does_not_unlock_high_through_inherited_ones():
    inherited = {"honeytoken": 1, "canary_path": 3, "rate": 2}
    assert inherited_tier({"generic_client": 1}, inherited)[0] == "medium"
    assert inherited_tier({"canary_path": 1}, inherited)[0] == "high"
    assert inherited_tier({"scanner_ua": 1, "attack_payload": 1, "rate": 1}, inherited)[0] == "high"
