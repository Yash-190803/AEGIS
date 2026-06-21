import unittest

from app import app, detector, metrics, vectorizer


BRUTE_FORCE_LOGS = [
    f"Jun 20 10:23:{second % 40:02d} webserver sshd[1234]: Failed password for root from 203.0.113.45 port {52300 + second} ssh2"
    for second in range(80)
]

BENIGN_LOGS = [
    "Jun 20 10:23:01 appserver nginx: GET /health 200 from 10.0.0.10 port 443",
    "Jun 20 10:23:03 appserver nginx: GET /api/status 200 from 10.0.0.11 port 443",
    "Jun 20 10:23:06 appserver nginx: POST /api/login 200 from 10.0.0.12 port 443",
]


class ScorerEndpointTest(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()

    def test_health_reports_loaded_model(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn(payload["status"], {"healthy", "degraded"})
        self.assertEqual(payload["version"], "1.0.0")
        self.assertTrue(payload["modelLoaded"])
        self.assertTrue(payload["baselineLoaded"])

    def test_score_escalates_brute_force_batch(self):
        response = self.client.post(
            "/score",
            json={"batchId": "unit-brute-force", "logType": "AUTH", "logs": BRUTE_FORCE_LOGS},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["batchId"], "unit-brute-force")
        self.assertEqual(payload["recommendation"], "ESCALATE_TO_LLM")
        self.assertGreaterEqual(payload["anomalyScore"], 0.7)
        self.assertGreaterEqual(payload["confidence"], 0.8)
        self.assertGreater(len(payload["flaggedLines"]), 0)
        self.assertTrue(any("known bad IP" in item["reasons"] for item in payload["flaggedLines"]))
        self.assertEqual(payload["batchFeatures"]["failed_auth_count"], len(BRUTE_FORCE_LOGS))

    def test_score_discards_or_monitors_benign_batch(self):
        response = self.client.post(
            "/score",
            json={"batchId": "unit-benign", "logType": "APPLICATION", "logs": BENIGN_LOGS},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn(payload["recommendation"], {"DISCARD", "MONITOR"})
        self.assertLess(payload["confidence"], 0.9)
        self.assertEqual(payload["batchFeatures"]["sql_pattern_count"], 0)
        self.assertEqual(payload["batchFeatures"]["shell_pattern_count"], 0)

    def test_score_rejects_invalid_payload(self):
        response = self.client.post("/score", json={"logType": "AUTH", "logs": []})
        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.get_json())

    def test_metrics_endpoint_tracks_scoring(self):
        before = metrics["total_scored"]
        self.client.post("/score", json={"batchId": "unit-metrics", "logType": "AUTH", "logs": BRUTE_FORCE_LOGS})
        response = self.client.get("/metrics")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertGreaterEqual(payload["total_scored"], before + 1)
        self.assertGreaterEqual(payload["averageLatencyMs"], 0)
        self.assertTrue(payload["modelLoaded"])

    def test_retrain_accepts_feature_vector_feedback(self):
        vector = vectorizer.batch_to_numeric_vector(BENIGN_LOGS, "APPLICATION")
        response = self.client.post("/retrain", json={"examples": [{"features": vector}]})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "retrained")
        self.assertGreaterEqual(payload["result"]["new_examples"], 1)
        self.assertTrue(detector.is_trained)


if __name__ == "__main__":
    unittest.main()
