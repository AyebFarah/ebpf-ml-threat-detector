"""
Thin adapter: the graph index has run_id, label and scenario columns, which
is all detection.data.split.group_stratified_split needs. Same function and
same seed as Layer 1, so the runs land in the same train, val and test sets.
"""
from __future__ import annotations

from detection.config import RANDOM_SEED
from detection.data.split import group_stratified_split


def split_positions(index, verbose: bool = True):
    """Returns three arrays of row positions: train, val, test."""
    indexed = index.assign(pos=range(len(index)))
    parts = group_stratified_split(indexed, seed=RANDOM_SEED, verbose=verbose)
    return tuple(p["pos"].to_numpy() for p in parts)


def run_ids_of(index, positions) -> list[int]:
    return sorted(int(r) for r in index.iloc[positions].run_id.unique())