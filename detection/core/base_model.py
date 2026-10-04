from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np
import pandas as pd


class BaseDetectionModel(ABC):
    """
    Every Layer 1 model must implement this. Training code, evaluation
    code and the live inference wrapper only ever call these four
    methods. They never import lightgbm, xgboost or sklearn directly.

    This is what makes adding a new algorithm safe: a new file that
    implements this contract plugs into training, evaluation, and
    inference automatically. No existing file needs to change.
    """

    name: str = "base"
    artifact_filename: str = "model.bin"

    def __init__(self, params: dict | None = None):
        self.params = params or {}
        self.model = None

    @abstractmethod
    def fit(self, X_train: pd.DataFrame, y_train, X_val: pd.DataFrame, y_val) -> "BaseDetectionModel":
        ...

    @abstractmethod
    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        ...

    @abstractmethod
    def save(self, path: str) -> None:
        ...

    @classmethod
    @abstractmethod
    def load(cls, path: str) -> "BaseDetectionModel":
        ...

    def feature_importance(self) -> dict[str, float] | None:
        """Optional. A model that can rank its own features overrides this."""
        return None