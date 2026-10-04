import importlib
import logging

log = logging.getLogger(__name__)

_MODULES = (
    "lightgbm_model", "xgboost_model", "random_forest_model",
    "logistic_regression_model", "rule_based_model",
    "isolation_forest_model", "hdbscan_model", "xgbod_model",
    "residual_regression_model",
)

for _name in _MODULES:
    try:
        importlib.import_module(f"{__name__}.{_name}")
    except ImportError as exc:
        log.warning("algorithm %s skipped, missing dependency: %s", _name, exc)