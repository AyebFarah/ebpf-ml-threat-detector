"""
Hand-written rule-based baseline, for the "compare against traditional
rule-based detection" requirement in the project brief. Thresholds are
illustrative, not tuned per scenario -- the point is a legible baseline
to measure the ML models against, not a strong detector in its own right.
"""
from __future__ import annotations

import pandas as pd

RULES = {
    "port_scan": lambda r: (r.get("unique_dst_port_count") or 0) > 20
                           and (r.get("dst_port_entropy") or 0) > 3.0,
    "ssh_bruteforce": lambda r: (r.get("ssh_failure_ratio") or 0) > 0.7
                                and (r.get("ssh_attempt_count") or 0) > 5,
    "dns_tunneling": lambda r: (r.get("nxdomain_ratio") or 0) > 0.3
                               or (r.get("hex_like_ratio") or 0) > 0.5
                               or (r.get("base32_like_ratio") or 0) > 0.5,
    "high_connection_rate": lambda r: (r.get("connections_per_sec") or 0) > 10,
    "rare_tls_fingerprint": lambda r: (r.get("rare_ja4_ratio") or 0) > 0.8,
    "sensitive_file_after_privesc": lambda r: (r.get("sensitive_file_event_count") or 0) > 0
                                              and (r.get("sudo_exec_count") or 0) > 0,
}

def score_row(row: dict) -> tuple[int, list[str]]:
    """Returns (0/1, [names of rules that fired])."""
    fired = [name for name, rule in RULES.items() if rule(row)]
    return (1 if fired else 0), fired

def score_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    results = df.apply(lambda row: score_row(row.to_dict()), axis=1)
    df = df.copy()
    df["rule_prediction"] = [r[0] for r in results]
    df["rules_fired"] = [",".join(r[1]) for r in results]
    return df