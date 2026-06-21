import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

from models.anomaly_detector import AnomalyDetector
from models.log_vectorizer import LogVectorizer

VERSION = "1.0.0"
ROOT_DIR = Path(__file__).resolve().parent
BASELINE_PATH = ROOT_DIR / "data" / "baseline_metrics.json"
MODEL_PATH = ROOT_DIR / "models" / "saved_model.pkl"
load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format="%(asctime)s %(levelname)s [aegis-ml] %(message)s")
logger = logging.getLogger("aegis-ml")
app = Flask(__name__)
CORS(app)
vectorizer = LogVectorizer()
detector = AnomalyDetector()
baseline_metrics = {}
service_ready = False
startup_error = None
started_at = datetime.now(timezone.utc)
metrics = dict(
    total_scored=0,
    escalated=0,
    discarded=0,
    monitored=0,
    failed_requests=0,
    retrain_count=0,
    total_latency_ms=0.0,
    last_score_at=None,
    last_retrain_at=None,
)

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def load_baseline_metrics():
    if not BASELINE_PATH.exists():
        raise FileNotFoundError(f"baseline metrics not found at {BASELINE_PATH}")
    with BASELINE_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict) or "featureOrder" not in payload:
        raise ValueError("baseline metrics must contain featureOrder")
    return payload

def initialize_service():
    global baseline_metrics, service_ready, startup_error
    try:
        baseline_metrics = load_baseline_metrics()
        loaded = detector.load(str(MODEL_PATH))
        if loaded:
            logger.info("Loaded saved anomaly model from %s", MODEL_PATH)
        else:
            training_summary = detector.train_on_baseline()
            detector.save(str(MODEL_PATH))
            logger.info("Trained anomaly model from baseline: %s", training_summary)
        service_ready = True
        startup_error = None
    except Exception as exc:
        service_ready = False
        startup_error = str(exc)
        logger.exception("ML service initialization failed")

def validate_score_payload(payload):
    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")
    logs = payload.get("logs")
    log_type = payload.get("logType", "APPLICATION")
    batch_id = payload.get("batchId", f"ml-batch-{int(time.time() * 1000)}")
    if not isinstance(logs, list) or not logs:
        raise ValueError("logs must be a non-empty array")
    if len(logs) > 1000:
        raise ValueError("logs may contain at most 1000 entries")
    if any(not isinstance(line, str) or not line.strip() for line in logs):
        raise ValueError("each log entry must be a non-empty string")
    if not isinstance(log_type, str) or not log_type.strip():
        raise ValueError("logType must be a non-empty string")
    if not isinstance(batch_id, str) or not batch_id.strip():
        raise ValueError("batchId must be a non-empty string")
    return logs, log_type.upper(), batch_id

def score_line(features):
    weights = {
        "failed_auth_flag": 0.18,
        "success_auth_flag": 0.02,
        "sql_injection_flag": 0.34,
        "shell_command_flag": 0.32,
        "has_external_ip": 0.08,
        "unusual_port_flag": 0.08,
        "unusual_hour_flag": 0.05,
        "line_length_normalized": 0.05,
        "known_bad_ip_flag": 0.28,
    }
    score = sum(features.get(name, 0) * weight for name, weight in weights.items())
    if features.get("known_bad_ip_flag") and features.get("failed_auth_flag"):
        score += 0.18
    if features.get("sql_injection_flag") and features.get("has_external_ip"):
        score += 0.12
    return round(max(0.0, min(1.0, score)), 3)

def line_reasons(features):
    reasons = []
    labels = {
        "failed_auth_flag": "failed authentication",
        "success_auth_flag": "successful authentication",
        "sql_injection_flag": "SQL injection pattern",
        "shell_command_flag": "shell command pattern",
        "has_external_ip": "external IP",
        "unusual_port_flag": "unusual port",
        "unusual_hour_flag": "unusual hour",
        "known_bad_ip_flag": "known bad IP",
    }
    for key, label in labels.items():
        if features.get(key):
            reasons.append(label)
    return reasons

def calculate_confidence(logs, anomaly_score, batch_features, line_features):
    size_component = min(len(logs) / 80.0, 0.25)
    signal_count = sum(
        1
        for key in ("failed_auth_count", "sql_pattern_count", "shell_pattern_count")
        if batch_features.get(key, 0) > 0
    )
    known_bad_count = sum(item.get("known_bad_ip_flag", 0) for item in line_features)
    confidence = 0.5 + size_component + min(signal_count * 0.08, 0.18)
    if anomaly_score >= 0.7:
        confidence += 0.12
    if known_bad_count:
        confidence += 0.12
    if len(logs) < baseline_metrics.get("confidenceCalibration", {}).get("minimumBatchSizeForHighConfidence", 20):
        confidence -= baseline_metrics.get("confidenceCalibration", {}).get("smallBatchPenalty", 0.15)
    return round(max(0.0, min(0.99, confidence)), 3)

def flagged_lines(logs, line_features, line_scores):
    flagged = [
        {"index": index, "score": score, "line": logs[index], "reasons": line_reasons(line_features[index])}
        for index, score in enumerate(line_scores)
        if score >= 0.35 or line_features[index].get("known_bad_ip_flag")
    ]
    return sorted(flagged, key=lambda item: item["score"], reverse=True)[:25]

def update_score_metrics(recommendation, elapsed_ms):
    metrics["total_scored"] += 1
    metrics["total_latency_ms"] += elapsed_ms
    metrics["last_score_at"] = utc_now()
    if recommendation == "ESCALATE_TO_LLM":
        metrics["escalated"] += 1
    elif recommendation == "MONITOR":
        metrics["monitored"] += 1
    else:
        metrics["discarded"] += 1

def error_response(message, status_code=400):
    metrics["failed_requests"] += 1
    logger.warning("Request failed: %s", message)
    return jsonify({"error": message}), status_code

def normalized_feedback_examples(examples):
    vectors = []
    for example in examples:
        if isinstance(example, dict) and isinstance(example.get("logs"), list):
            log_type = str(example.get("logType", "APPLICATION")).upper()
            vectors.append(vectorizer.batch_to_numeric_vector(example["logs"], log_type))
        else:
            vectors.append(example)
    return vectors

@app.route("/health", methods=["GET"])
def health():
    try:
        status = "healthy" if service_ready and detector.is_trained else "degraded"
        return jsonify(
            {
                "status": status,
                "modelLoaded": detector.is_trained,
                "version": VERSION,
                "baselineLoaded": bool(baseline_metrics),
                "startupError": startup_error,
                "uptimeSeconds": round((datetime.now(timezone.utc) - started_at).total_seconds(), 3),
            }
        )
    except Exception as exc:
        logger.exception("Health endpoint failed")
        return jsonify({"error": str(exc)}), 500

@app.route("/score", methods=["POST"])
def score():
    started = time.perf_counter()
    try:
        if not service_ready:
            initialize_service()
        if not service_ready:
            return error_response(f"ML service unavailable: {startup_error}", 503)
        logs, log_type, batch_id = validate_score_payload(request.get_json(silent=True))
        line_features = vectorizer.extract_features(logs, log_type)
        batch_features = vectorizer.extract_batch_features(logs, log_type)
        batch_vector = vectorizer.batch_to_numeric_vector(logs, log_type)
        anomaly_score = round(detector.score_batch([batch_vector])[0], 3)
        line_scores = [score_line(features) for features in line_features]
        confidence = calculate_confidence(logs, anomaly_score, batch_features, line_features)
        recommendation = detector.get_recommendation(anomaly_score, confidence)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        update_score_metrics(recommendation, elapsed_ms)
        return jsonify(
            {
                "batchId": batch_id,
                "logType": log_type,
                "anomalyScore": anomaly_score,
                "confidence": confidence,
                "recommendation": recommendation,
                "flaggedLines": flagged_lines(logs, line_features, line_scores),
                "lineScores": [
                    {"index": index, "score": line_scores[index], "features": line_features[index]}
                    for index in range(len(logs))
                ],
                "batchFeatures": batch_features,
                "modelLoaded": detector.is_trained,
                "fallback": False,
                "latencyMs": elapsed_ms,
                "scoredAt": utc_now(),
            }
        )
    except ValueError as exc:
        return error_response(str(exc), 400)
    except Exception as exc:
        logger.exception("Score endpoint failed")
        return error_response(str(exc), 500)

@app.route("/retrain", methods=["POST"])
def retrain():
    try:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error_response("request body must be a JSON object", 400)
        examples = payload.get("examples")
        if not isinstance(examples, list) or not examples:
            return error_response("examples must be a non-empty array", 400)
        vectors = normalized_feedback_examples(examples)
        result = detector.update_with_feedback(vectors)
        detector.save(str(MODEL_PATH))
        metrics["retrain_count"] += 1
        metrics["last_retrain_at"] = utc_now()
        return jsonify({"status": "retrained", "result": result, "modelPath": str(MODEL_PATH)})
    except ValueError as exc:
        return error_response(str(exc), 400)
    except Exception as exc:
        logger.exception("Retrain endpoint failed")
        return error_response(str(exc), 500)

@app.route("/metrics", methods=["GET"])
def service_metrics():
    try:
        total = max(metrics["total_scored"], 1)
        return jsonify(
            {
                **metrics,
                "averageLatencyMs": round(metrics["total_latency_ms"] / total, 3),
                "uptimeSeconds": round((datetime.now(timezone.utc) - started_at).total_seconds(), 3),
                "modelLoaded": detector.is_trained,
                "trainingExamples": len(detector.training_vectors),
            }
        )
    except Exception as exc:
        logger.exception("Metrics endpoint failed")
        return jsonify({"error": str(exc)}), 500

def main():
    initialize_service()
    port = int(os.getenv("ML_SERVICE_PORT", "5001"))
    host = os.getenv("ML_SERVICE_HOST", "0.0.0.0")
    logger.info("Starting AEGIS ML service on %s:%s", host, port)
    from waitress import serve

    serve(app, host=host, port=port, threads=4)


initialize_service()

if __name__ == "__main__":
    main()
