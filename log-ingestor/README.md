# AEGIS Log Ingestor

Go service that tails enterprise log files, batches newly appended lines, and ships them to the AEGIS Node.js backend through the internal ingestion API.

## Role In AEGIS

The ingestor watches `data/logs` for `.log` files. It follows existing files, detects newly-created log files, normalizes each line with file path, line number, timestamp, and inferred log type, then posts batches to:

```text
POST /api/internal/log-batch
```

The Node.js backend converts those batches into `LOG_BATCH_RECEIVED` events for SentinelAgent.

## Prerequisites

- Go 1.22+
- Running AEGIS Node.js backend
- `INTERNAL_API_KEY` matching the Node `.env` value

## Install Dependencies

From the `log-ingestor` directory:

```bash
go mod download
go mod verify
```

## Configuration

Default config file: `config.yaml`

```yaml
watchDirectory: ../data/logs
nodeBackendURL: http://localhost:3000
batchSize: 100
batchTimeoutMs: 1000
retryAttempts: 3
retryBackoffMs: 500
internalApiKey: ${INTERNAL_API_KEY}
```

| Key | Description |
|---|---|
| `watchDirectory` | Directory containing `.log` files to follow. |
| `nodeBackendURL` | Base URL for the Node.js backend or full internal log-batch URL. |
| `batchSize` | Flush batch when this many lines are collected. |
| `batchTimeoutMs` | Flush partial batch after this many milliseconds. |
| `retryAttempts` | Delivery attempts per batch before dropping and continuing. |
| `retryBackoffMs` | Initial retry delay; retries use exponential backoff. |
| `internalApiKey` | Shared secret sent as `X-Internal-Api-Key`. Environment variables are expanded. |

## Run

```bash
set INTERNAL_API_KEY=aegis-internal-key-dev
go run . -config config.yaml
```

PowerShell:

```powershell
$env:INTERNAL_API_KEY = "aegis-internal-key-dev"
go run . -config config.yaml
```

Linux or macOS:

```bash
export INTERNAL_API_KEY=aegis-internal-key-dev
go run . -config config.yaml
```

Expected startup message:

```text
AEGIS Log Ingestor started. Watching: ../data/logs
```

## Build

```bash
go build -o aegis-log-ingestor .
```

On Windows:

```powershell
go build -o aegis-log-ingestor.exe .
```

## Log Type Inference

The tailer infers `logType` from the file name:

| Filename Contains | Log Type |
|---|---|
| `auth` | `AUTH` |
| `network` | `NETWORK` |
| `system` | `SYSTEM` |
| anything else | `APPLICATION` |

## Batch Payload

The shipper posts batches in this format:

```json
{
  "batchId": "uuid-v4",
  "timestamp": "2026-06-21T10:00:00Z",
  "source": "go-log-ingestor",
  "lines": [
    {
      "timestamp": "2026-06-21T10:00:00Z",
      "filePath": "../data/logs/auth.log",
      "logType": "AUTH",
      "lineNumber": 42,
      "content": "Jun 20 10:23:01 webserver sshd[1234]: Failed password for root from 203.0.113.45 port 52300 ssh2"
    }
  ]
}
```

## Rotation Behavior

`TailFile` seeks to the end on startup, reads only newly appended lines, and reopens the path if the file is deleted, recreated, replaced, or truncated. This supports common log rotation patterns without restarting the ingestor.

## Shutdown

Press `Ctrl+C` or send `SIGTERM`. The process cancels tailers, flushes remaining lines, waits for the shipper, and prints:

```text
Log Ingestor shutdown
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `watchDirectory must exist` | Create the configured directory or update `watchDirectory` in `config.yaml`. |
| `internalApiKey is required` | Set `INTERNAL_API_KEY` or replace the config value with the local development key. |
| Backend returns HTTP 401 | Ensure the key matches `INTERNAL_API_KEY` in the Node `.env`. |
| No lines are shipped | The tailer starts at end-of-file; append new lines after starting the ingestor. |
| `go mod download` fails offline | Run the command from a networked environment so Go can fetch `fsnotify` and `yaml.v3`. |