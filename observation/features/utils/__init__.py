"""Pure, dependency-free helper functions used across feature groups.

No database access, no domain knowledge of correlated_events, entity
types, or windowing. Anything added here should be testable in complete
isolation, with plain values in, plain values out.

- entropy.py         Shannon entropy over a distribution of counts.
- ip_utils.py         Private/external IP classification.
- string_features.py  DNS-label heuristics (base32/64/hex-like ratios,
                       label entropy) used by dns_features in groups.py.
"""