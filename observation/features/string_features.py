import re
import math
from statistics import mean

BASE32_RE = re.compile(r"^[A-Z2-7]+=*$", re.IGNORECASE)
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+=*$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _label_entropy(label: str) -> float:
    if not label:
        return 0.0
    counts = {}
    for ch in label:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(label)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def domain_label_stats(domains: list[str]) -> dict:
    """Per-domain-label heuristics used as DNS-tunneling indicators.
    Operates on the first (leftmost/subdomain) label of each domain,
    which is where tunneling payloads are typically encoded."""
    if not domains:
        return {
            "mean_label_length": None, "max_label_length": None,
            "domain_label_entropy_mean": None,
            "base32_like_ratio": None, "base64_like_ratio": None,
            "hex_like_ratio": None,
            "mean_domain_length": None, "max_domain_length": None,
            "subdomain_depth_mean": None,
        }

    first_labels = [d.split(".")[0] for d in domains if d]
    lengths = [len(l) for l in first_labels]
    domain_lengths = [len(d) for d in domains]
    depths = [d.count(".") for d in domains]

    base32_hits = sum(1 for l in first_labels if len(l) >= 8 and BASE32_RE.match(l))
    base64_hits = sum(1 for l in first_labels if len(l) >= 8 and BASE64_RE.match(l))
    hex_hits = sum(1 for l in first_labels if len(l) >= 8 and HEX_RE.match(l))
    n = len(first_labels) or 1

    return {
        "mean_label_length": mean(lengths) if lengths else None,
        "max_label_length": max(lengths) if lengths else None,
        "domain_label_entropy_mean": mean(_label_entropy(l) for l in first_labels) if first_labels else None,
        "base32_like_ratio": base32_hits / n,
        "base64_like_ratio": base64_hits / n,
        "hex_like_ratio": hex_hits / n,
        "mean_domain_length": mean(domain_lengths) if domain_lengths else None,
        "max_domain_length": max(domain_lengths) if domain_lengths else None,
        "subdomain_depth_mean": mean(depths) if depths else None,
    }