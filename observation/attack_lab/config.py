import ipaddress

# Only these subnets may ever be targeted by an attack script. Anything
# outside this list is refused by the wrapper before the pipeline even
# starts, this is the last line of defense against accidentally pointing
# an attack tool at a real network.
ALLOWED_TARGET_SUBNETS = [
    "192.168.56.0/24",
    "192.168.100.0/24",
]

INTENSITY_PROFILES = {
    "low": {"description": "Low-intensity, minimal footprint"},
    "medium": {"description": "Medium-intensity, realistic attack"},
    "high": {"description": "High-intensity, stress-test"},
}


def is_target_allowed(host: str | None) -> bool:
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    allowed_nets = [ipaddress.ip_network(net) for net in ALLOWED_TARGET_SUBNETS]
    return any(ip in net for net in allowed_nets)