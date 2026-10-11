"""ML Configuration for Baseline Isolation Forest Anomaly Detection.

Loads paths and model hyperparameters from environment variables or defaults.
Ensures reproducible seeds and documented threshold-selection parameters.
"""

from pathlib import Path
from typing import Optional, Union
import os
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

ROOT = Path(__file__).resolve().parents[2]


class MLConfig(BaseModel):
    """Configuration settings for baseline ML training, inference, and evaluation."""

    data_dir: Path = Field(
        default_factory=lambda: Path(os.getenv("DATA_DIR", str(ROOT / "data"))).resolve()
    )
    artifact_dir: Path = Field(
        default_factory=lambda: Path(
            os.getenv("ARTIFACT_DIR", str(ROOT / "artifacts"))
        ).resolve() / "ml"
    )

    # Dataset filenames
    train_filename: str = "security_windows_train_normal.csv"
    eval_filename: str = "security_windows_eval_labeled.csv"

    # Isolation Forest hyperparameters
    random_state: int = 42
    n_estimators: int = 100
    max_samples: Union[str, int, float] = "auto"
    contamination: Union[str, float] = "auto"

    # Threshold selection parameters (derived from normal training distribution)
    # 95th percentile corresponds to an expected ~5% false-positive rate on normal training behavior
    threshold_percentile: float = 95.0
    threshold_method: str = "training_normal_percentile"

    @property
    def train_path(self) -> Path:
        return self.data_dir / self.train_filename

    @property
    def eval_path(self) -> Path:
        return self.data_dir / self.eval_filename

    @property
    def preprocessor_artifact_path(self) -> Path:
        return self.artifact_dir / "preprocessor.joblib"

    @property
    def model_artifact_path(self) -> Path:
        return self.artifact_dir / "isolation_forest.joblib"

    @property
    def threshold_artifact_path(self) -> Path:
        return self.artifact_dir / "threshold.json"

    @property
    def feature_schema_artifact_path(self) -> Path:
        return self.artifact_dir / "feature_schema.json"

    @property
    def metrics_artifact_path(self) -> Path:
        return self.artifact_dir / "metrics.json"


def get_default_config() -> MLConfig:
    """Retrieve default ML configuration."""
    return MLConfig()
