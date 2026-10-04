import numpy as np
import pandas as pd

from detection.layer2.seq_model import GRUModel
from detection.layer2.sequence import make_sequences


def test_sequences_are_causal_padded_and_isolated_by_run():
    index = pd.DataFrame({
        "run_id": [1, 1, 1, 2],
        "window_start_ts": ["2026-01-01T00:00:10+00:00", "2026-01-01T00:00:00+00:00",
                            "2026-01-01T00:00:05+00:00", "2026-01-01T00:00:00+00:00"],
    })
    stats = pd.DataFrame({"a": [3.0, 1.0, 2.0, 9.0]})
    seq = make_sequences(stats, index, length=3)
    assert seq.shape == (4, 3, 1)
    assert np.allclose(np.expm1(seq[0, :, 0]), [1, 2, 3])   # latest window, full history
    assert np.allclose(np.expm1(seq[1, :, 0]), [1, 1, 1])   # first window, padded
    assert np.allclose(np.expm1(seq[3, :, 0]), [9, 9, 9])   # run 2 never sees run 1


def test_gru_fit_predict_save_load_roundtrip(tmp_path):
    rng = np.random.default_rng(0)
    X = rng.normal(size=(64, 6, 18)).astype("float32")
    y = (X[:, -1, 0] > 0).astype(int)
    model = GRUModel({"epochs": 3}).fit(X, y, X, y)
    before = model.predict_proba(X)
    model.save(str(tmp_path / "m.pt"))
    after = GRUModel.load(str(tmp_path / "m.pt")).predict_proba(X)
    assert before.shape == (64,) and np.allclose(before, after, atol=1e-5)