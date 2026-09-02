import re

ATTACK_LABEL_RE = re.compile(r"^attack:[a-z0-9_]+:T\d{4}(\.\d{3})?$")


def validate_label(label: str) -> None:
    if label == "benign":
        return
    if not ATTACK_LABEL_RE.match(label):
        raise ValueError(
            f"Invalid label '{label}'. Must be 'benign' or "
            f"'attack:<family>:<technique>' where family is lowercase/"
            f"underscore and technique matches MITRE format Txxxx or "
            f"Txxxx.xxx, e.g. 'attack:ssh_bruteforce:T1110.001'."
        )