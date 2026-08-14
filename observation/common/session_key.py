def session_key(src_ip, src_port, username):
    """
    Canonical SSH session identity: the client's (src_ip, src_port) plus
    the authenticated username. This is the single definition used by
    both ssh-collector.py (to tag events as they're collected) and
    correlator.py (to re-join those events into sessions later).
    """
    if src_ip is None or src_port is None or username is None:
        return None
    return f"{src_ip}:{src_port}:{username}"
