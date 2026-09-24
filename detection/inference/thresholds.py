"""
Per-layer decision thresholds, centralized so tuning one number doesn't
require editing training or replay code.

These are FALLBACK values only, used when a real trained model's tuned
threshold (from its metrics.json, via layer1.predict.load_tuned_threshold)
isn't available (e.g. before a model has ever been trained). Once a
model exists, prefer its own tuned threshold: LightGBM is trained with
scale_pos_weight (class reweighting), which changes what predict_proba's
output means and makes 0.5 an unreliable default, see
evaluation.metrics.find_best_threshold's docstring for why. Don't treat
the 0.5 below as a real decision boundary, it's a last resort.

The layer2/layer3 entries are placeholders until those layers exist.
"""

THRESHOLDS = {
    "layer1": 0.5,
    "layer2": 0.5,
    "layer3": None,  # Layer 3 doesn't threshold a score, it reasons over what layer1/2 already flagged
}
