from __future__ import annotations

from detection.core.base_model import BaseDetectionModel

_REGISTRY: dict[str, type] = {}
_FAMILY: dict[str, str] = {}

def family_of(name: str) -> str:
    return _FAMILY[name]

def register_model(name: str, family: str = "tabular"):
    def _wrap(cls):
        _REGISTRY[name] = cls
        _FAMILY[name] = family
        return cls
    return _wrap


def get_model_class(name: str) -> type:
    if name not in _REGISTRY:
        raise ValueError(f"Unknown model '{name}'. Registered models: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


def available_models(family: str | None = "tabular") -> list[str]:
    return sorted(n for n, f in _FAMILY.items() if family is None or f == family)