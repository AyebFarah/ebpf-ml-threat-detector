"""
Sequence models (GRU, LSTM, 1D CNN) for Layer 2. They expose the same four
methods as BaseDetectionModel and are registered with family="sequence", so
artifacts.load_bundle finds them and the tabular compare run ignores them.
Input: an array of shape (windows, steps, statistics).
"""
from __future__ import annotations

import copy

import numpy as np
import torch
from torch import nn

from detection.config import RANDOM_SEED
from detection.core.registry import register_model
from detection.evaluation.metrics import evaluate_scores

DEFAULT_PARAMS = {
    "hidden": 32, "dropout": 0.3, "lr": 0.003, "weight_decay": 1e-4,
    "epochs": 100, "patience": 15, "batch_size": 128,
}


class SeqNet(nn.Module):
    def __init__(self, kind: str, in_dim: int, hidden: int, dropout: float):
        super().__init__()
        self.kind = kind
        if kind == "cnn":
            self.body = nn.Sequential(nn.Conv1d(in_dim, hidden, 3, padding=1), nn.ReLU(),
                                      nn.Conv1d(hidden, hidden, 3, padding=1), nn.ReLU())
            head_in = 2 * hidden
        else:
            recurrent = nn.GRU if kind == "gru" else nn.LSTM
            self.body = recurrent(in_dim, hidden, batch_first=True)
            head_in = hidden
        self.head = nn.Sequential(nn.Linear(head_in, hidden), nn.ReLU(),
                                  nn.Dropout(dropout), nn.Linear(hidden, 1))

    def forward(self, x):                       # x: (batch, steps, statistics)
        if self.kind == "cnn":
            h = self.body(x.transpose(1, 2))    # the CNN wants (batch, statistics, steps)
            pooled = torch.cat([h.mean(dim=2), h.amax(dim=2)], dim=1)
        else:
            out, _ = self.body(x)
            pooled = out[:, -1]                 # memory state after the newest window
        return self.head(pooled).squeeze(-1)


class _SequenceModel:
    name = "sequence"
    kind = "gru"
    artifact_filename = "model.pt"

    def __init__(self, params: dict | None = None):
        self.params = {**DEFAULT_PARAMS, **(params or {})}
        self.net, self.in_dim, self.mean, self.std = None, None, None, None

    def _build(self, in_dim: int) -> None:
        p = self.params
        self.in_dim = in_dim
        self.net = SeqNet(self.kind, in_dim, p["hidden"], p["dropout"])

    def _scale(self, X) -> torch.Tensor:
        scaled = (np.asarray(X, dtype=np.float32) - self.mean) / self.std
        return torch.from_numpy(scaled.astype(np.float32))

    def fit(self, X_train, y_train, X_val, y_val):
        torch.manual_seed(RANDOM_SEED)
        p = self.params
        X_train = np.asarray(X_train, dtype=np.float32)
        flat = X_train.reshape(-1, X_train.shape[-1])
        self.mean, self.std = flat.mean(axis=0), np.maximum(flat.std(axis=0), 1e-6)  # train only
        self._build(X_train.shape[-1])

        y = np.asarray(y_train, dtype=np.float32)
        x, target = self._scale(X_train), torch.from_numpy(y)
        pos_weight = torch.tensor([float((y == 0).sum()) / max(float((y == 1).sum()), 1.0)])
        loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        optimizer = torch.optim.Adam(self.net.parameters(), lr=p["lr"], weight_decay=p["weight_decay"])

        best_score, best_state, waited = -1.0, None, 0
        for epoch in range(1, p["epochs"] + 1):
            self.net.train()
            order, total = torch.randperm(len(x)), 0.0
            for start in range(0, len(x), p["batch_size"]):
                idx = order[start:start + p["batch_size"]]
                optimizer.zero_grad()
                loss = loss_fn(self.net(x[idx]), target[idx])
                loss.backward()
                optimizer.step()
                total += float(loss.detach()) * len(idx)

            val_pr = evaluate_scores(y_val, self.predict_proba(X_val), verbose=False)["pr_auc"] or 0.0
            if val_pr > best_score:
                best_score, best_state, waited = val_pr, copy.deepcopy(self.net.state_dict()), 0
            else:
                waited += 1
            if epoch % 5 == 0 or epoch == 1:
                print(f"[{self.name}] epoch {epoch:3d}  train loss {total / len(x):.4f}"
                      f"  val PR AUC {val_pr:.4f}")
            if waited >= p["patience"]:
                print(f"[{self.name}] early stop at epoch {epoch}, best val PR AUC {best_score:.4f}")
                break
        self.net.load_state_dict(best_state)
        return self

    def predict_proba(self, X) -> np.ndarray:
        self.net.eval()
        x = self._scale(X)
        with torch.no_grad():
            parts = [torch.sigmoid(self.net(x[i:i + 1024])).numpy() for i in range(0, len(x), 1024)]
        return np.concatenate(parts) if parts else np.array([])

    def save(self, path: str) -> None:
        torch.save({"params": self.params, "in_dim": self.in_dim,
                    "mean": torch.from_numpy(self.mean.astype(np.float32)),
                    "std": torch.from_numpy(self.std.astype(np.float32)),
                    "state_dict": self.net.state_dict()}, path)

    @classmethod
    def load(cls, path: str):
        blob = torch.load(path, map_location="cpu", weights_only=True)
        model = cls(blob["params"])
        model.mean, model.std = blob["mean"].numpy(), blob["std"].numpy()
        model._build(blob["in_dim"])
        model.net.load_state_dict(blob["state_dict"])
        model.net.eval()
        return model

    def feature_importance(self):
        return None


@register_model("gru", family="sequence")
class GRUModel(_SequenceModel):
    name, kind = "gru", "gru"


@register_model("lstm", family="sequence")
class LSTMModel(_SequenceModel):
    name, kind = "lstm", "lstm"


@register_model("cnn", family="sequence")
class CNNModel(_SequenceModel):
    name, kind = "cnn", "cnn"