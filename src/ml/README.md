# ML service

The ML service provides local model status, inference, synthetic-data generation, and retraining for the host-monitoring prototype.

## Model

The current classifier is a scikit-learn RandomForest trained on generated examples. Features combine numeric process measurements with derived indicators such as sensitive-file access, suspicious execution location, shell/network behavior, resource use, and selected destination ports.

Because the training data is synthetic, reported train/test metrics are integration signals rather than evidence of real-world detection quality.

## Endpoints

- `GET /ml/status` — model readiness and feature metadata.
- `POST /ml/predict` — single-event inference.
- `POST /ml/predict/batch` — bounded batch inference.
- `GET /ml/report` — latest local training report.
- `POST /ml/generate` — generate synthetic data; control token required.
- `POST /ml/retrain` — retrain the model; control token required.

Generation and retraining paths are constrained to `AISEC_DATA_DIR` (default `data/`) to prevent API input from reading or writing arbitrary host paths.
