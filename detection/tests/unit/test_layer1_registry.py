"""
Confirms the plugin mechanism works: registration, lookup, and that a class missing
a required method fails at instantiation instead of deep inside training.
"""
import pytest

import detection.algorithms  # noqa: F401  triggers registration
from detection.core.base_model import BaseDetectionModel
from detection.core.registry import available_models, get_model_class, register_model


def test_known_models_are_registered():
    names = available_models()
    for expected in ("lightgbm", "xgboost", "logistic_regression", "rules"):
        assert expected in names, f"'{expected}' missing, check its @register_model decorator"


def test_unknown_model_name_raises_clear_error():
    with pytest.raises(ValueError, match="Unknown model"):
        get_model_class("definitely_not_a_real_model")


def test_incomplete_model_cannot_be_instantiated():
    @register_model("_incomplete_test_model")
    class _Incomplete(BaseDetectionModel):
        name = "_incomplete_test_model"

    with pytest.raises(TypeError):
        _Incomplete()