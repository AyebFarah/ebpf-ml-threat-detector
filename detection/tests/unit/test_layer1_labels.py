from detection.data.labels import (ATTACK_FAMILY_DESCRIPTIONS, NEAR_MISS_LOOKALIKE,
                                   NEAR_MISS_SCENARIOS, describe, scenario_kind)

# Families that really exist in merged_observations.db (from run_summary.txt).
OBSERVED_FAMILIES = ("port_scan", "network_discovery", "ssh_bruteforce", "lateral_movement",
                     "command_and_control", "exfiltration", "dns_tunneling")


def test_every_observed_family_has_a_description():
    for family in OBSERVED_FAMILIES:
        assert family in ATTACK_FAMILY_DESCRIPTIONS, f"no description for '{family}'"


def test_describe_handles_benign_and_unknown_families():
    assert describe(None) == "benign"
    assert describe("some_new_family") == "some_new_family"


def test_scenario_kind_separates_attack_near_miss_and_benign():
    assert scenario_kind(1, "port_scan") == "attack"
    assert scenario_kind(0, "ssh_retry_storm") == "near_miss"
    assert scenario_kind(0, "mixed_workday") == "benign"


def test_every_near_miss_imitates_a_known_family():
    assert set(NEAR_MISS_LOOKALIKE) == set(NEAR_MISS_SCENARIOS)
    assert set(NEAR_MISS_LOOKALIKE.values()) <= set(ATTACK_FAMILY_DESCRIPTIONS)