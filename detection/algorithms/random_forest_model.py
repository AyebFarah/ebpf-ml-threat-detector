from sklearn.ensemble import RandomForestClassifier
from detection.core.base_model import BaseDetectionModel
from detection.core.registry import register_model
import joblib

@register_model("random_forest")
class RandomForestModel(BaseDetectionModel):
    name = "random_forest"
    artifact_filename = "model.joblib"

    def fit(self, X_train, y_train, X_val, y_val):
        self.model = RandomForestClassifier(n_estimators=300, class_weight="balanced", **self.params)
        self.model.fit(X_train.fillna(-999), y_train)
        return self

    def predict_proba(self, X):
        return self.model.predict_proba(X.fillna(-999))[:, 1]

    def save(self, path):
        joblib.dump(self.model, path)

    @classmethod
    def load(cls, path):
        instance = cls()
        instance.model = joblib.load(path)
        return instance