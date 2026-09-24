"""
The attack taxonomy as it appears in feature_windows.attack_family /
.attack_technique, plus human-readable descriptions for alerts and
reports. Kept separate from schema.py since this is about label
semantics, not which columns are numeric features.

Extend ATTACK_FAMILY_DESCRIPTIONS as new scenarios are added under
observation/attacks/, nothing else needs to change.
"""

ATTACK_FAMILY_DESCRIPTIONS = {
    "port_scan": "Network/service discovery via port scanning",
    "ssh_bruteforce": "Repeated SSH authentication attempts",
    "command_and_control": "Beaconing to a C2 channel",
    "exfiltration": "Outbound data transfer to an external host",
    "dns_tunneling": "Data encoded in DNS queries/responses",
    "network_discovery": "Host/service enumeration",
    "lateral_movement": "Movement between hosts via SSH or similar",
}


def describe(attack_family: str | None) -> str:
    if not attack_family:
        return "benign"
    return ATTACK_FAMILY_DESCRIPTIONS.get(attack_family, attack_family)
