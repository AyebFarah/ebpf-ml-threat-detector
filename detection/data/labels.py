"""
Label semantics for feature_windows: which attack families exist, which benign
scenarios are deliberate near misses, and how to describe them in alerts and reports.

Family versus scenario:
  scenario = the script that was run (c2_beacon, lateral_movement_ssh)
  family   = the label stored in the database (command_and_control, lateral_movement)
"""
from __future__ import annotations

ATTACK_FAMILY_DESCRIPTIONS = {
    "port_scan": "TCP port scanning of one target to find open services",
    "network_discovery": "Broad host and service enumeration across the subnet",
    "ssh_bruteforce": "Many SSH password guesses against one account",
    "lateral_movement": "Moving to another host with valid SSH credentials",
    "command_and_control": "Regular outbound beacons to a control server",
    "exfiltration": "Bulk outbound data transfer to an external host",
    "dns_tunneling": "Data hidden in many random looking DNS names",
}

# Benign on purpose, but shaped like an attack. Used to measure false alarms.
NEAR_MISS_SCENARIOS = frozenset({
    "dev_dns_burst", "ssh_retry_storm", "admin_backup_rsync", "admin_nmap_inventory",
    "security_vuln_scan_light", "ops_log_collection", "ops_health_check",
})

# Which attack each near miss is meant to imitate (design intent, edit if you disagree).
NEAR_MISS_LOOKALIKE = {
    "dev_dns_burst": "dns_tunneling",
    "ssh_retry_storm": "ssh_bruteforce",
    "admin_backup_rsync": "exfiltration",
    "admin_nmap_inventory": "port_scan",
    "security_vuln_scan_light": "network_discovery",
    "ops_log_collection": "lateral_movement",
    "ops_health_check": "command_and_control",
}


def describe(attack_family: str | None) -> str:
    if not attack_family:
        return "benign"
    return ATTACK_FAMILY_DESCRIPTIONS.get(attack_family, attack_family)


def scenario_kind(label, scenario: str) -> str:
    """'attack', 'near_miss' or 'benign'. Three groups tell a better story than two."""
    if int(label) == 1:
        return "attack"
    return "near_miss" if scenario in NEAR_MISS_SCENARIOS else "benign"