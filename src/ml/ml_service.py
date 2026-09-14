from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from shared.security import control_auth_configured, require_control_token
from src.ml.inference.predictor import Predictor
from src.ml.training.train_pipeline import train_from_csv

logger = logging.getLogger("ml-service")
app = FastAPI(title="ML Intrusion Detection Service", version="1.1")

REPO_ROOT = Path(__file__).resolve().parents[2]
_data_setting = Path(os.getenv("AISEC_DATA_DIR", "data"))
DATA_ROOT = (_data_setting if _data_setting.is_absolute() else REPO_ROOT / _data_setting).resolve()
MODEL_DIR = DATA_ROOT / "models"
MODEL_PATH = MODEL_DIR / "classifier_pipeline.joblib"
REPORT_PATH = MODEL_DIR / "train_report.json"
DEFAULT_SYNTHETIC_PATH = DATA_ROOT / "synthetic" / "synthetic_events.csv"

predictor: Predictor | None = None


class PredictRequest(BaseModel):
    event: Dict[str, Any]


class PredictBatchRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(min_length=1, max_length=500)


class RetrainRequest(BaseModel):
    csv_path: str = "data/synthetic/synthetic_events.csv"
    n_normal: int = Field(default=3000, ge=50, le=100_000)
    n_attack: int = Field(default=1000, ge=50, le=100_000)
    regenerate: bool = False


class GenerateDataRequest(BaseModel):
    n_normal: int = Field(default=3000, ge=50, le=100_000)
    n_attack: int = Field(default=1000, ge=50, le=100_000)
    output_path: str = "data/synthetic/synthetic_events.csv"


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _resolve_data_path(raw_path: str, *, suffix: str | None = None) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        # Preserve the public API's historical ``data/...`` paths while allowing
        # AISEC_DATA_DIR to relocate generated artifacts outside the repository.
        parts = path.parts[1:] if path.parts and path.parts[0] == "data" else path.parts
        path = DATA_ROOT.joinpath(*parts)
    path = path.resolve()

    if not path.is_relative_to(DATA_ROOT):
        raise HTTPException(status_code=400, detail="path must stay inside the configured data directory")
    if suffix and path.suffix.lower() != suffix.lower():
        raise HTTPException(status_code=400, detail=f"path must end with {suffix}")
    return path


def _reload_predictor() -> None:
    global predictor
    predictor = Predictor(str(MODEL_PATH))


@app.on_event("startup")
def _load_model() -> None:
    global predictor
    try:
        _reload_predictor()
        logger.info("loaded model from %s", _display_path(MODEL_PATH))
    except FileNotFoundError:
        predictor = None
        logger.info("no model artifact found; run setup or POST /ml/retrain")
    except Exception:
        predictor = None
        logger.exception("failed to load model artifact")


@app.get("/ml/status")
def status() -> Dict[str, Any]:
    feature_names = predictor.feature_names if predictor is not None else []
    return {
        "ready": predictor is not None,
        "control_auth_configured": control_auth_configured(),
        "model_path": _display_path(MODEL_PATH),
        "feature_count": len(feature_names),
        "features": feature_names,
        "supported_threats": [
            "sensitive_file_access",
            "privilege_escalation",
            "suspicious_exec",
            "crypto_miner",
            "reverse_shell",
            "data_exfiltration",
        ],
    }


@app.post("/ml/predict")
def predict(req: PredictRequest) -> Dict[str, Any]:
    if predictor is None:
        return {
            "ok": False,
            "error": "model is not loaded",
            "label": 0,
            "score": 0.0,
            "action": "allow",
        }

    try:
        return predictor.predict_one(req.event)
    except Exception as exc:
        logger.exception("single-event prediction failed")
        return {
            "ok": False,
            "error": type(exc).__name__,
            "label": 0,
            "score": 0.0,
            "action": "allow",
        }


@app.post("/ml/predict/batch")
def predict_batch(req: PredictBatchRequest) -> Dict[str, Any]:
    if predictor is None:
        return {"ok": False, "error": "model is not loaded"}
    try:
        return predictor.predict_batch(req.events)
    except Exception as exc:
        logger.exception("batch prediction failed")
        return {"ok": False, "error": type(exc).__name__}


@app.post("/ml/generate", dependencies=[Depends(require_control_token)])
def generate_data(req: GenerateDataRequest) -> Dict[str, Any]:
    from src.ml.data_generator.synthetic_generator import save_synthetic_csv

    output_path = _resolve_data_path(req.output_path, suffix=".csv")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path = save_synthetic_csv(
            path=str(output_path),
            n_normal=req.n_normal,
            n_attack=req.n_attack,
        )
    except Exception as exc:
        logger.exception("synthetic data generation failed")
        raise HTTPException(status_code=500, detail="data generation failed") from exc

    return {
        "ok": True,
        "path": _display_path(Path(path).resolve()),
        "n_normal": req.n_normal,
        "n_attack": req.n_attack,
    }


@app.post("/ml/retrain", dependencies=[Depends(require_control_token)])
def retrain(req: RetrainRequest) -> Dict[str, Any]:
    global predictor

    csv_path = _resolve_data_path(req.csv_path, suffix=".csv")
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    try:
        if req.regenerate:
            from src.ml.data_generator.synthetic_generator import save_synthetic_csv

            csv_path.parent.mkdir(parents=True, exist_ok=True)
            save_synthetic_csv(
                path=str(csv_path),
                n_normal=req.n_normal,
                n_attack=req.n_attack,
            )

        artifacts, report = train_from_csv(
            csv_path=str(csv_path),
            model_dir=str(MODEL_DIR),
        )
        _reload_predictor()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="training data not found") from exc
    except Exception as exc:
        logger.exception("model retraining failed")
        raise HTTPException(status_code=500, detail="model training failed") from exc

    classification = report["classification_report"]
    return {
        "ok": True,
        "model_path": _display_path(Path(artifacts.model_path).resolve()),
        "report_path": _display_path(Path(artifacts.report_path).resolve()),
        "metrics": {
            "accuracy": classification["accuracy"],
            "f1_macro": classification["macro avg"]["f1-score"],
            "precision_attack": classification.get("1", {}).get("precision", 0),
            "recall_attack": classification.get("1", {}).get("recall", 0),
        },
        "cv_f1_mean": report.get("cv_f1_mean", 0),
        "feature_count": len(artifacts.feature_names),
    }


@app.get("/ml/report")
def get_report() -> Dict[str, Any]:
    if not REPORT_PATH.exists():
        raise HTTPException(status_code=404, detail="no training report found")
    with REPORT_PATH.open("r", encoding="utf-8") as handle:
        report = json.load(handle)
    return {"ok": True, "report": report}
