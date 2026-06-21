package shipper

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aegis/log-ingestor/internal/tailer"
)

const (
	defaultBatchSize      = 100
	defaultBatchTimeoutMs = 1000
	defaultRetryAttempts  = 3
	defaultRetryBackoffMs = 500
	requestTimeout        = 10 * time.Second
)

// Config controls batching and delivery to the Node.js AEGIS backend.
type Config struct {
	NodeBackendURL string
	BatchSize      int
	BatchTimeoutMs int
	RetryAttempts  int
	RetryBackoffMs int
	InternalAPIKey string
}

type batchPayload struct {
	BatchID   string           `json:"batchId"`
	Timestamp string           `json:"timestamp"`
	Lines     []tailer.LogLine `json:"lines"`
	Source    string           `json:"source"`
}

// BatchAndShip reads LogLines, batches them, and POSTs each batch to Node.js.
// Batches flush when BatchSize is reached, BatchTimeoutMs elapses, the input
// channel closes, or the context is cancelled. Delivery failures are retried
// with exponential backoff; after all retries fail the error is logged and the
// ingestor continues processing later batches.
//
// @param ctx Context used for graceful shutdown.
// @param in Channel of normalized log lines from tailer.TailFile.
// @param cfg Delivery and retry configuration.
func BatchAndShip(ctx context.Context, in <-chan tailer.LogLine, cfg Config) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		log.Printf("shipper configuration error: %v", err)
		return
	}
	client := &http.Client{Timeout: requestTimeout}
	timeout := time.Duration(normalized.BatchTimeoutMs) * time.Millisecond
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	batch := make([]tailer.LogLine, 0, normalized.BatchSize)
	resetTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(timeout)
	}
	flush := func(reason string) {
		if len(batch) == 0 {
			return
		}
		lines := append([]tailer.LogLine(nil), batch...)
		batch = batch[:0]
		if err := postWithRetries(ctx, client, normalized, lines); err != nil {
			log.Printf("shipper dropped batch after retries reason=%s lines=%d error=%v", reason, len(lines), err)
			return
		}
		log.Printf("shipper delivered batch reason=%s lines=%d", reason, len(lines))
	}

	for {
		select {
		case <-ctx.Done():
			flush("shutdown")
			return
		case line, ok := <-in:
			if !ok {
				flush("input_closed")
				return
			}
			batch = append(batch, line)
			if len(batch) >= normalized.BatchSize {
				flush("batch_size")
				resetTimer()
			}
		case <-timer.C:
			flush("timeout")
			resetTimer()
		}
	}
}

func normalizeConfig(cfg Config) (Config, error) {
	if strings.TrimSpace(cfg.NodeBackendURL) == "" {
		return cfg, errors.New("nodeBackendURL is required")
	}
	if strings.TrimSpace(cfg.InternalAPIKey) == "" {
		return cfg, errors.New("internalAPIKey is required")
	}
	endpoint, err := endpointURL(cfg.NodeBackendURL)
	if err != nil {
		return cfg, err
	}
	cfg.NodeBackendURL = endpoint
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.BatchTimeoutMs <= 0 {
		cfg.BatchTimeoutMs = defaultBatchTimeoutMs
	}
	if cfg.RetryAttempts <= 0 {
		cfg.RetryAttempts = defaultRetryAttempts
	}
	if cfg.RetryBackoffMs <= 0 {
		cfg.RetryBackoffMs = defaultRetryBackoffMs
	}
	return cfg, nil
}

func endpointURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse nodeBackendURL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("nodeBackendURL must include scheme and host: %s", raw)
	}
	path := strings.TrimRight(parsed.Path, "/")
	if path == "" {
		parsed.Path = "/api/internal/log-batch"
	} else if !strings.HasSuffix(path, "/api/internal/log-batch") {
		parsed.Path = path + "/api/internal/log-batch"
	} else {
		parsed.Path = path
	}
	return parsed.String(), nil
}

func postWithRetries(ctx context.Context, client *http.Client, cfg Config, lines []tailer.LogLine) error {
	var lastErr error
	for attempt := 1; attempt <= cfg.RetryAttempts; attempt++ {
		if err := postBatch(ctx, client, cfg, lines); err != nil {
			lastErr = err
			if attempt == cfg.RetryAttempts || ctx.Err() != nil {
				break
			}
			wait := time.Duration(cfg.RetryBackoffMs) * time.Millisecond * time.Duration(1<<(attempt-1))
			log.Printf("shipper retry attempt=%d wait=%s error=%v", attempt, wait, err)
			if err := sleepWithContext(ctx, wait); err != nil {
				return err
			}
			continue
		}
		return nil
	}
	return fmt.Errorf("all %d delivery attempts failed: %w", cfg.RetryAttempts, lastErr)
}

func postBatch(ctx context.Context, client *http.Client, cfg Config, lines []tailer.LogLine) error {
	payload := batchPayload{
		BatchID:   generateUUID(),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Lines:     lines,
		Source:    "go-log-ingestor",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal batch payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.NodeBackendURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create batch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Api-Key", cfg.InternalAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post batch: %w", err)
	}
	defer resp.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if readErr != nil {
		return fmt.Errorf("read backend response: %w", readErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("backend HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func generateUUID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("batch-%d", time.Now().UnixNano())
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(bytes)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32])
}
