"""
Maps feature_windows columns to the feature group that produced them
(the same categories used in observation/features/groups.py), so model
feature importance can be reported and compared at the group level
rather than as a flat list of 90+ individual columns.

Group membership is a keyword match against each column's name. A new
feature column is picked up automatically as long as it follows the
existing naming convention (a dns_ prefix, an _ssh_ prefix, and so on),
no manual list of every column needs to be maintained.
"""
from __future__ import annotations

FEATURE_GROUPS: dict[str, tuple[str, ...]] = {
    "basic_counts": ("event_count", "flow_count", "window_"),
    "network_topology": ("dst_ip", "src_ip", "dst_port", "src_port", "unique_dst",
                         "unique_src", "ip_entropy", "port_entropy", "external_ip", "private_ip"),
    "traffic_volume": ("bytes_", "packets_"),
    "flow_dynamics": ("duration", "termination"),
    "rate_and_burstiness": ("_per_sec", "burst", "connections_per"),
    "dns_features": ("dns_", "nxdomain", "base32_like", "base64_like", "hex_like",
                     "domain_label_entropy", "ttl"),
    "tls_features": ("tls_", "ja4", "sni"),
    "http_features": ("http_",),
    "process_features": ("process_", "exec_", "binary_count", "shell_spawn",
                         "interpreter_spawn", "parent_"),
    "privilege_and_file_features": ("privilege_", "sudo_", "sensitive_file",
                                    "file_activity", "capability"),
    "ssh_features": ("ssh_",),
}

OTHER_GROUP = "other"


def assign_group(feature_name: str) -> str:
    lowered = feature_name.lower()
    for group, keywords in FEATURE_GROUPS.items():
        if any(keyword in lowered for keyword in keywords):
            return group
    return OTHER_GROUP


def aggregate_importance_by_group(importances: dict[str, float]) -> dict[str, float]:
    """Sums raw per feature importance into its group, then normalizes
    to a percentage of the total, so models with different raw scales
    (LightGBM gain, XGBoost gain, a linear model's coefficients) end up
    comparable on the same 0 to 100 axis."""
    totals: dict[str, float] = {}
    for feature, score in importances.items():
        group = assign_group(feature)
        totals[group] = totals.get(group, 0.0) + abs(float(score))

    grand_total = sum(totals.values())
    if grand_total == 0:
        return {group: 0.0 for group in totals}
    return {group: (value / grand_total) * 100.0 for group, value in totals.items()}