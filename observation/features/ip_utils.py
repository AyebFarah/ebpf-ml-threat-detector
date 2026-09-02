import ipaddress


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_external_ip(ip: str) -> bool:
    return ip is not None and not is_private_ip(ip)