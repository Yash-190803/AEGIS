# AEGIS ML Service

Python anomaly scoring microservice for AEGIS log batches. It vectorizes raw security logs, scores them with an Isolation Forest model, and returns a recommendation before the Node.js agents spend OpenAI tokens.

## Role In AEGIS

The ML service sits in front of SentinelAgent. For every log batch, Sentinel calls `/score` first:

- `DISCARD` means the batch appears normal and can be skipped when confidence is high.
- `MONITOR` means the batch is mildly suspicious and should be tracked without an immediate LLM call.
- `ESCALATE_TO_LLM` means the batch should continue to GPT-4o analysis.

If the service is down, the Node.js client falls back to LLM-only mode.

## Prerequisites

- Python 3.11+
- `pip`
- AEGIS repository dependencies from `requirements.txt`

## Install

From the `ml-service` directory:

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r requirements.txt
```

On Linux or macOS, activate with:

```bash
. .venv/bin/activate
```

## Run

```bash
ML_SERVICE_PORT=5001 python app.py
```

The service uses Waitress, not the Flask development server. By default it listens on `0.0.0.0:5001`.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Reports service health, model load status, version, and uptime. |
| `POST` | `/score` | Scores a batch of raw logs and returns anomaly score, confidence, recommendation, flagged lines, and extracted features. |
| `POST` | `/retrain` | Accepts feedback examples and retrains the model with the new vectors. |
| `GET` | `/metrics` | Returns scoring counts, recommendations, latency, retraining count, and model size. |

## Score Request

```json
{
  "batchId": "demo-auth-001",
  "logType": "AUTH",
  "logs": [
    "Jun 20 10:23:01 webserver sshd[1234]: Failed password for root from 203.0.113.45 port 52300 ssh2"
  ]
}
```

## Score Response

```json
{
  "batchId": "demo-auth-001",
  "logType": "AUTH",
  "anomalyScore": 0.82,
  "confidence": 0.91,
  "recommendation": "ESCALATE_TO_LLM",
  "flaggedLines": [
    {
      "index": 0,
      "score": 0.64,
      "line": "Jun 20 10:23:01 webserver sshd[1234]: Failed password for root from 203.0.113.45 port 52300 ssh2",
      "reasons": ["failed authentication", "external IP", "known bad IP"]
    }
  ],
  "fallback": false
}
```

## Model Behavior

`models/log_vectorizer.py` extracts per-line and batch features:

- Authentication failures and successes
- SQL injection and shell command patterns
- External and known-bad IP indicators
- Unusual ports and unusual hours
- Request rate and source IP cardinality

`models/anomaly_detector.py` trains an Isolation Forest from synthetic normal and anomalous baselines on first startup. It saves the trained model to `models/saved_model.pkl` and reloads it on later starts.

## Retraining

Feedback examples can be numeric feature vectors:

```json
{
  "examples": [
    {
      "features": [80, 80, 0, 1.0, 1, 0, 0, 120, 0.0]
    }
  ]
}
```

They can also include raw logs:

```json
{
  "examples": [
    {
      "logType": "AUTH",
      "logs": [
        "Jun 20 10:23:01 webserver sshd[1234]: Failed password for root from 203.0.113.45 port 52300 ssh2"
      ]
    }
  ]
}
```

The endpoint retrains under a lock and saves the updated model.

## Tests

From the `ml-service` directory:

```bash
python -m pytest tests/ -v --tb=short
```

The tests use Flask's test client and cover health, scoring, validation, metrics, and retraining.

## Configuration

| Variable | Default | Description |
|---|---:|---|
| `ML_SERVICE_PORT` | `5001` | Waitress port. |
| `ML_SERVICE_HOST` | `0.0.0.0` | Waitress bind host. |
| `LOG_LEVEL` | `INFO` | Python logging level. |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'dotenv'` | Run `pip install -r requirements.txt` inside `ml-service`. |
| `/health` returns `degraded` | Check that `data/baseline_metrics.json` exists and can be parsed. |
| Model file is missing | Start the service once; it trains and saves `models/saved_model.pkl` automatically. |
| `/score` returns HTTP 400 | Ensure `logs` is a non-empty array of strings and `logType` is a string. |
| Node.js falls back to LLM-only mode | Confirm this service is running on the URL configured by `ML_SERVICE_URL`. |