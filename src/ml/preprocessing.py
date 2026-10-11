"""Preprocessing pipeline for baseline Isolation Forest detector.

Ensures strict column ordering, numeric validation, and deterministic feature extraction.
Tree-based Isolation Forest does not require feature scaling; preprocessor focuses on
schema alignment and type safety.
"""

from pathlib import Path
from typing import List, Optional, Union
import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

from src.ml.features import NUMERIC_BEHAVIORAL_FEATURES, validate_feature_schema


class FeaturePreprocessor(BaseEstimator, TransformerMixin):
    """Deterministic feature selector and validator for ML anomaly detection."""

    def __init__(self, feature_names: Optional[List[str]] = None):
        self.feature_names = (
            list(feature_names) if feature_names else list(NUMERIC_BEHAVIORAL_FEATURES)
        )
        self.is_fitted_ = False

    def fit(self, X: pd.DataFrame, y=None):
        """Fit preprocessor by validating training schema and locking feature ordering."""
        if not isinstance(X, pd.DataFrame):
            raise TypeError(f"Expected pandas DataFrame, got {type(X)}")

        validate_feature_schema(X, self.feature_names)
        self.is_fitted_ = True
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Extract features in exact expected order as float64 numpy array."""
        if not self.is_fitted_:
            raise ValueError("FeaturePreprocessor is not fitted yet.")

        if not isinstance(X, pd.DataFrame):
            raise TypeError(f"Expected pandas DataFrame, got {type(X)}")

        validate_feature_schema(X, self.feature_names)

        # Extract features in strict canonical order
        sub_df = X[self.feature_names]
        arr = sub_df.to_numpy(dtype=np.float64, copy=True)

        # Ensure no infinite or NaN values
        if not np.all(np.isfinite(arr)):
            raise ValueError("Input features contain infinite or non-finite values.")

        return arr

    def save(self, file_path: Union[str, Path]) -> None:
        """Serialize fitted preprocessor using joblib."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @classmethod
    def load(cls, file_path: Union[str, Path]) -> "FeaturePreprocessor":
        """Load serialized preprocessor."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Preprocessor artifact not found at {path}")
        obj = joblib.load(path)
        if not isinstance(obj, cls):
            raise TypeError(f"Loaded object is not a FeaturePreprocessor instance: {type(obj)}")
        return obj
