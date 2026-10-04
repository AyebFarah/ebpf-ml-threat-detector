"""
Graph neural network models. They expose the same four methods as
BaseDetectionModel (fit, predict_proba, save, load) in the same argument
order, but take a list of graphs instead of a DataFrame, so they are not
subclasses of it. Registering them with family="graph" keeps them out of
the tabular `compare` run while artifacts.load_bundle still finds them.
"""
from __future__ import annotations

import copy

import numpy as np
import torch
import torch.nn.functional as F
from torch import nn
from torch_geometric.loader import DataLoader
from torch_geometric.nn import (GCNConv, SAGEConv, global_add_pool, global_max_pool,
                                global_mean_pool)

from detection.config import RANDOM_SEED
from detection.core.registry import register_model
from detection.evaluation.metrics import evaluate_scores

DEFAULT_PARAMS = {
    "hidden": 32, "layers": 2, "dropout": 0.3, "lr": 0.005,
    "weight_decay": 1e-4, "epochs": 100, "patience": 15, "batch_size": 64,
}


class GraphNet(nn.Module):
    def __init__(self, conv: str, in_dim: int, hidden: int, layers: int, dropout: float):
        super().__init__()
        Conv = GCNConv if conv == "gcn" else SAGEConv
        dims = [in_dim] + [hidden] * layers
        self.convs = nn.ModuleList(Conv(dims[i], dims[i + 1]) for i in range(layers))
        self.dropout = dropout
        self.head = nn.Sequential(nn.Linear(3 * hidden, hidden), nn.ReLU(),
                                  nn.Dropout(dropout), nn.Linear(hidden, 1))

    def forward(self, data):
        x = data.x
        for conv in self.convs:
            x = F.dropout(F.relu(conv(x, data.edge_index)), self.dropout, self.training)
        pooled = torch.cat([
            global_mean_pool(x, data.batch),                 # the typical node
            global_max_pool(x, data.batch),                  # the most extreme node
            torch.log1p(global_add_pool(x, data.batch)),     # the total, so size is visible
        ], dim=1)
        return self.head(pooled).squeeze(-1)


class _GraphModel:
    name = "graph"
    conv = "sage"
    artifact_filename = "model.pt"

    def __init__(self, params: dict | None = None):
        self.params = {**DEFAULT_PARAMS, **(params or {})}
        self.net = None

    def _build(self, in_dim: int) -> None:
        p = self.params
        self.in_dim = in_dim
        self.net = GraphNet(self.conv, in_dim, p["hidden"], p["layers"], p["dropout"])

    def fit(self, train_graphs, y_train, val_graphs, y_val):
        torch.manual_seed(RANDOM_SEED)
        p = self.params
        self._build(train_graphs[0].x.shape[1])

        y_train = np.asarray(y_train)
        pos = float((y_train == 1).sum())
        neg = float((y_train == 0).sum())
        loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([neg / max(pos, 1.0)]))
        optimizer = torch.optim.Adam(self.net.parameters(), lr=p["lr"], weight_decay=p["weight_decay"])
        loader = DataLoader(train_graphs, batch_size=p["batch_size"], shuffle=True)

        best_score, best_state, waited = -1.0, None, 0
        for epoch in range(1, p["epochs"] + 1):
            self.net.train()
            total = 0.0
            for batch in loader:
                optimizer.zero_grad()
                loss = loss_fn(self.net(batch), batch.y)
                loss.backward()
                optimizer.step()
                total += float(loss.detach()) * batch.num_graphs

            val_pr = evaluate_scores(y_val, self.predict_proba(val_graphs), verbose=False)["pr_auc"] or 0.0
            if val_pr > best_score:
                best_score, best_state, waited = val_pr, copy.deepcopy(self.net.state_dict()), 0
            else:
                waited += 1
            if epoch % 5 == 0 or epoch == 1:
                print(f"[{self.name}] epoch {epoch:3d}  train loss {total / len(train_graphs):.4f}"
                      f"  val PR AUC {val_pr:.4f}")
            if waited >= p["patience"]:
                print(f"[{self.name}] early stop at epoch {epoch}, best val PR AUC {best_score:.4f}")
                break
        self.net.load_state_dict(best_state)
        return self

    def predict_proba(self, graphs) -> np.ndarray:
        self.net.eval()
        out = []
        with torch.no_grad():
            for batch in DataLoader(list(graphs), batch_size=256):
                out.append(torch.sigmoid(self.net(batch)).numpy())
        return np.concatenate(out) if out else np.array([])

    def save(self, path: str) -> None:
        torch.save({"params": self.params, "in_dim": self.in_dim,
                    "state_dict": self.net.state_dict()}, path)

    @classmethod
    def load(cls, path: str):
        blob = torch.load(path, map_location="cpu", weights_only=True)
        model = cls(blob["params"])
        model._build(blob["in_dim"])
        model.net.load_state_dict(blob["state_dict"])
        model.net.eval()
        return model

    def feature_importance(self):
        return None


@register_model("graphsage", family="graph")
class GraphSAGEModel(_GraphModel):
    name, conv = "graphsage", "sage"


@register_model("gcn", family="graph")
class GCNModel(_GraphModel):
    name, conv = "gcn", "gcn"