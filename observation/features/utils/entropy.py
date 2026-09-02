import math


def shannon_entropy(counts: list[int]) -> float:
    """Shannon entropy over a distribution of counts. 0.0 for a single
    destination hit repeatedly (idle/low-fanout); higher for many distinct,
    evenly-hit destinations (browsing, scanning)."""
    total = sum(counts)
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)
    return entropy