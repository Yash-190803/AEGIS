# AEGIS

Autonomous Enterprise Guard & Intelligent Security Swarm: a multi-agent AI cybersecurity platform with a Node.js agent backend, Python anomaly scoring service, Go log ingestor, and live Socket.io dashboard.

## Architecture

```text
                              +----------------------+
                              |  Browser Dashboard   |
                              |  HTML/CSS/JS + WS    |
                              +----------+-----------+
                                         |
                                         v
+----------------------+      +----------+-----------+      +----------------------+
| Go Log Ingestor      | ---> | Node.js AEGIS API    | ---> | SharedMemory         |
| tails data/logs/*.log |      | Express + Socket.io  |      | incidents/audit/HITL |
+----------+-----------+      +----------+-----------+      +----------+-----------+
           |                             |                             ^
           |                             v                             |
           |                  +----------+-----------+                 |
           +----------------> | MessageBus Events    | ----------------+
                              +----------+-----------+
                                         |
        +--------------------------------+--------------------------------+
        |                                                                 |
        v                                                                 v
+-------+--------+  +---------------+  +-------------+  +----------------+  +---------------+
| Orchestrator   |  | Sentinel      |  | IntelFusion |  | Triage         |  | Response      |
| routes/HITL    |  | detection     |  | enrichment  |  | risk/level     |  | containment   |
+----------------+  +-------+-------+  +-------------+  +----------------+  +---------------+
                           |
                           v
                  +--------+---------+
                  | Python ML Service|
                  | IsolationForest  |
                  +------------------+

+----------------+  +---------------+  +---------------+  +----------------+
| Forensics      |  | RedTeam       |  | Deception     |  | Audit          |
| reports        |  | simulations   |  | honeypots     |  | compliance log |
+----------------+  +---------------+  +---------------+  +----------------+
```

## Prerequisites

- Node.js 20+
- Python 3.11+
- Go 1.22+
- Docker Desktop, optional for Compose
- Jenkins, optional for CI/CD

## Installation

```bash
git clone <your-repo-url> aegis
cd aegis
npm install
cd ml-service && pip install -r requirements.txt && cd ..
cd log-ingestor && go mod download && cd ..
copy .env.example .env
```

Edit `.env` and set `OPENAI_API_KEY` to a real key for live AI calls.

## Running

Use three terminals:

```bash
npm start
```

```bash
cd ml-service
python app.py
```

```bash
cd log-ingestor
go run . -config config.yaml
```

Dashboard: `http://localhost:3000`

Optional Compose run:

```bash
docker compose up
```

## Mock Mode

Mock mode exercises the full agent pipeline without spending API credits. Set these values in `.env`:

```text
MOCK_MODE=true
OPENAI_API_KEY=sk-test-local
```

The key only needs the `sk-` prefix to satisfy startup validation in mock mode; it is not used for API calls.

## Demo Scenarios

| Scenario | Trigger | Expected behavior |
|---|---|---|
| `BRUTE_FORCE` | `curl -X POST http://localhost:3000/api/scenarios/run -H "Content-Type: application/json" -d "{\"scenario\":\"BRUTE_FORCE\"}"` | Sentinel detects SSH brute force, IntelFusion enriches `203.0.113.45`, Triage assigns level 3, Response blocks the IP in simulated state. |
| `RANSOMWARE_LATERAL` | `curl -X POST http://localhost:3000/api/scenarios/run -H "Content-Type: application/json" -d "{\"scenario\":\"RANSOMWARE_LATERAL\"}"` | Ransomware and lateral movement produce high risk, response level 4, and a mandatory HITL approval gate. |
| `SLOW_EXFILTRATION` | `curl -X POST http://localhost:3000/api/scenarios/run -H "Content-Type: application/json" -d "{\"scenario\":\"SLOW_EXFILTRATION\"}"` | Low-and-slow DNS activity stays subtle, then canary file access drives deception and monitoring signals. |

## Agents

| Agent | Description |
|---|---|
| OrchestratorAgent | Coordinates the detection-to-audit pipeline and owns HITL escalation routing. It also updates global threat level and schedules background red-team hardening. |
| SentinelAgent | Processes logs with ML pre-scoring, fast regex filters, and GPT-backed analysis. It emits standardized `THREAT_DETECTED` messages when evidence crosses detection thresholds. |
| IntelFusionAgent | Extracts indicators, checks local threat feeds, and maps behavior to MITRE ATT&CK. It escalates severity when CISA KEV, known infrastructure, or actor patterns match. |
| TriageAgent | Converts enriched evidence into risk scores, response levels, and business impact. Levels 4 and 5 always set `requiresHITL: true`. |
| ResponseAgent | Executes level 1-3 simulated actions with pre-logs, post-logs, state updates, and rollback tokens. It never executes level 4 or 5 unless HITL approval is recorded. |
| ForensicsAgent | Collects evidence as soon as threats are detected and builds incident timelines. It writes JSON and Markdown reports under `data/reports/{incidentId}/`. |
| RedTeamAgent | Generates simulated attack logs, identifies detection gaps, and proposes new detection rules. It pushes rule improvements back into SharedMemory for Sentinel reload. |
| DeceptionAgent | Deploys simulated honeypots, canary assets, and attacker profiling hooks. Honeypot interactions produce attacker profiles and deception events. |
| AuditAgent | Subscribes to every MessageBus event and writes immutable audit records. It also creates compliance-focused records for response and HITL decisions. |

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Runtime health, uptime, active incident count, threat level, ML status, ingestor status, and token usage. |
| `GET` | `/api/incidents` | Active incidents sorted by priority; supports `status`, `severity`, and `limit`. |
| `GET` | `/api/incidents/:id` | Full incident record. |
| `GET` | `/api/incidents/:id/timeline` | Incident attack timeline from forensics data and audit trail. |
| `POST` | `/api/incidents/:id/rollback/:actionId` | Requests rollback of a response action. |
| `GET` | `/api/agents/status` | Current agent status snapshots from SharedMemory. |
| `GET` | `/api/hitl/pending` | Pending HITL approvals with remaining time. |
| `POST` | `/api/hitl/:incidentId/approve` | Approves a pending human decision gate. |
| `POST` | `/api/hitl/:incidentId/reject` | Rejects a pending human decision gate. |
| `GET` | `/api/reports/:incidentId` | Forensics report JSON for an incident. |
| `GET` | `/api/audit` | Audit trail entries with optional filters. |
| `POST` | `/api/scenarios/run` | Runs a demo scenario and sends logs to Sentinel. |
| `POST` | `/api/redteam/simulate` | Queues an immediate red-team simulation. |
| `GET` | `/api/deception/honeypots` | Active honeypots and hit counts. |
| `GET` | `/api/intel/indicators` | Known-bad indicator counts and recent indicators. |
| `POST` | `/api/internal/log-batch` | Internal Go ingestor endpoint protected by `X-Internal-Api-Key`. |

## HITL Workflow

Response levels 4 and 5 are hard stops. Triage marks those incidents with `requiresHITL: true`, Orchestrator creates a pending HITL request, and the dashboard shows the proposed action, reasoning, blast radius, and countdown timer.

Analysts approve or reject through `/api/hitl/:incidentId/approve` or `/api/hitl/:incidentId/reject`. ResponseAgent only executes high-impact actions when the incident has `hitlStatus: "APPROVED"`; otherwise it emits `HITL_REQUIRED` and stops.

## Red Team Feedback Loop

RedTeamAgent simulates realistic attack chains and writes generated attack logs into `data/logs`. It compares those steps against current detection rules, identifies missed behavior, generates concrete rule improvements, stores them in SharedMemory, and emits `DETECTION_RULES_UPDATED`.

SentinelAgent refreshes its regex cache on that event. The next scan validates whether the new rules catch the simulated behavior, turning offensive simulation into defensive hardening.

## Tests

```bash
npm test
```

```bash
cd ml-service
python -m unittest discover -s tests -p "test_*.py"
```

```bash
cd log-ingestor
go test ./...
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `OPENAI_API_KEY is required` | Copy `.env.example` to `.env` and set a real `sk-...` key, or use `OPENAI_API_KEY=sk-test-local` with `MOCK_MODE=true`. |
| `Cannot find module 'dotenv'` | Run `npm install` from the project root. |
| ML service import errors | Run `pip install -r requirements.txt` inside `ml-service`. |
| Go dependency download fails | Run `go mod download` from a networked environment, then rerun `go test ./...`. |
| No scenario incidents appear | Start the Node backend, ensure `MOCK_MODE=true` for local demos, then check `data/logs` and `/api/health`. |