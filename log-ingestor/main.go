package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aegis/log-ingestor/internal/shipper"
	"github.com/aegis/log-ingestor/internal/tailer"
	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

const (
	lineBufferSize        = 10000
	shutdownTimeout       = 30 * time.Second
	newFileReadyTimeout   = 2 * time.Second
	defaultBatchSize      = 100
	defaultBatchTimeoutMs = 1000
	defaultRetryAttempts  = 3
	defaultRetryBackoffMs = 500
	minimumRetryBackoffMs = 100
	maximumBatchSize      = 5000
	maximumBatchTimeoutMs = 60000
	maximumRetryAttempts  = 10
	maximumRetryBackoffMs = 30000
)

type ingestorConfig struct {
	WatchDirectory string `yaml:"watch_directory"`
	NodeBackendURL string `yaml:"node_backend_url"`
	BatchSize      int    `yaml:"batch_size"`
	BatchTimeoutMs int    `yaml:"batch_timeout_ms"`
	RetryAttempts  int    `yaml:"retry_attempts"`
	RetryBackoffMs int    `yaml:"retry_backoff_ms"`
	InternalAPIKey string `yaml:"internal_api_key"`
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to log ingestor config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	tailCtx, cancelTailers := context.WithCancel(context.Background())
	shipperCtx, cancelShipper := context.WithCancel(context.Background())
	defer cancelShipper()

	lines := make(chan tailer.LogLine, lineBufferSize)
	var tailerWG sync.WaitGroup
	var shipperWG sync.WaitGroup
	var watcherWG sync.WaitGroup
	startedTailers := make(map[string]bool)
	var startedMu sync.Mutex

	startTailer := func(path string) {
		cleanPath, err := filepath.Abs(filepath.Clean(path))
		if err != nil {
			log.Printf("skip tailer for %s: %v", path, err)
			return
		}
		startedMu.Lock()
		if startedTailers[cleanPath] {
			startedMu.Unlock()
			return
		}
		startedTailers[cleanPath] = true
		startedMu.Unlock()

		tailerWG.Add(1)
		go func() {
			defer tailerWG.Done()
			if err := tailer.TailFile(tailCtx, cleanPath, lines); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("tailer stopped for %s: %v", cleanPath, err)
			}
		}()
		log.Printf("tailing %s", cleanPath)
	}

	if err := startExistingTailers(cfg.WatchDirectory, startTailer); err != nil {
		log.Fatalf("start existing tailers: %v", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("create fsnotify watcher: %v", err)
	}
	defer watcher.Close()
	if err := watcher.Add(cfg.WatchDirectory); err != nil {
		log.Fatalf("watch directory %s: %v", cfg.WatchDirectory, err)
	}

	shipperWG.Add(1)
	go func() {
		defer shipperWG.Done()
		shipper.BatchAndShip(shipperCtx, lines, shipper.Config{
			NodeBackendURL: cfg.NodeBackendURL,
			BatchSize:      cfg.BatchSize,
			BatchTimeoutMs: cfg.BatchTimeoutMs,
			RetryAttempts:  cfg.RetryAttempts,
			RetryBackoffMs: cfg.RetryBackoffMs,
			InternalAPIKey: cfg.InternalAPIKey,
		})
	}()

	watcherWG.Add(1)
	go watchForNewLogFiles(tailCtx, watcher, cfg.WatchDirectory, startTailer, &watcherWG)

	fmt.Printf("AEGIS Log Ingestor started. Watching: %s\n", cfg.WatchDirectory)
	waitForSignal()
	fmt.Println("Shutdown signal received. Stopping AEGIS Log Ingestor...")

	cancelTailers()
	if err := watcher.Close(); err != nil {
		log.Printf("close watcher: %v", err)
	}
	watcherWG.Wait()
	tailerWG.Wait()
	close(lines)

	done := make(chan struct{})
	go func() {
		shipperWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownTimeout):
		log.Printf("shipper shutdown exceeded %s; cancelling in-flight delivery", shutdownTimeout)
		cancelShipper()
		<-done
	}
	fmt.Println("Log Ingestor shutdown")
}

func loadConfig(path string) (ingestorConfig, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return ingestorConfig{}, fmt.Errorf("read config: %w", err)
	}
	var cfg ingestorConfig
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(data))), &cfg); err != nil {
		return ingestorConfig{}, fmt.Errorf("parse yaml: %w", err)
	}
	return validateConfig(cfg)
}

func validateConfig(cfg ingestorConfig) (ingestorConfig, error) {
	if strings.TrimSpace(cfg.WatchDirectory) == "" {
		return cfg, errors.New("watchDirectory is required")
	}
	watchDir, err := filepath.Abs(filepath.Clean(cfg.WatchDirectory))
	if err != nil {
		return cfg, fmt.Errorf("resolve watchDirectory: %w", err)
	}
	info, err := os.Stat(watchDir)
	if err != nil {
		return cfg, fmt.Errorf("watchDirectory must exist: %w", err)
	}
	if !info.IsDir() {
		return cfg, fmt.Errorf("watchDirectory must be a directory: %s", watchDir)
	}
	if strings.TrimSpace(cfg.NodeBackendURL) == "" {
		return cfg, errors.New("nodeBackendURL is required")
	}
	parsed, err := url.Parse(strings.TrimSpace(cfg.NodeBackendURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return cfg, fmt.Errorf("nodeBackendURL must be a valid absolute URL: %s", cfg.NodeBackendURL)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return cfg, fmt.Errorf("nodeBackendURL scheme must be http or https: %s", parsed.Scheme)
	}
	if strings.TrimSpace(cfg.InternalAPIKey) == "" {
		return cfg, errors.New("internalApiKey is required")
	}
	cfg.WatchDirectory = watchDir
	cfg.NodeBackendURL = strings.TrimSpace(cfg.NodeBackendURL)
	cfg.InternalAPIKey = strings.TrimSpace(cfg.InternalAPIKey)
	cfg.BatchSize = clampDefault(cfg.BatchSize, defaultBatchSize, 1, maximumBatchSize)
	cfg.BatchTimeoutMs = clampDefault(cfg.BatchTimeoutMs, defaultBatchTimeoutMs, 100, maximumBatchTimeoutMs)
	cfg.RetryAttempts = clampDefault(cfg.RetryAttempts, defaultRetryAttempts, 1, maximumRetryAttempts)
	cfg.RetryBackoffMs = clampDefault(cfg.RetryBackoffMs, defaultRetryBackoffMs, minimumRetryBackoffMs, maximumRetryBackoffMs)
	return cfg, nil
}

func clampDefault(value int, fallback int, min int, max int) int {
	if value <= 0 {
		return fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func startExistingTailers(watchDirectory string, startTailer func(string)) error {
	entries, err := os.ReadDir(watchDirectory)
	if err != nil {
		return fmt.Errorf("read watchDirectory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !isLogFile(entry.Name()) {
			continue
		}
		startTailer(filepath.Join(watchDirectory, entry.Name()))
	}
	return nil
}

func watchForNewLogFiles(ctx context.Context, watcher *fsnotify.Watcher, watchDirectory string, startTailer func(string), wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Create == 0 || !isLogFile(event.Name) {
				continue
			}
			if err := waitForRegularFile(ctx, event.Name); err != nil {
				if !errors.Is(err, context.Canceled) {
					log.Printf("new log file not ready %s: %v", event.Name, err)
				}
				continue
			}
			log.Printf("detected new log file in %s: %s", watchDirectory, event.Name)
			startTailer(event.Name)
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("watcher error: %v", err)
		}
	}
}

func waitForRegularFile(ctx context.Context, path string) error {
	deadline := time.Now().Add(newFileReadyTimeout)
	for {
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return nil
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for regular file")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func isLogFile(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".log")
}

func waitForSignal() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	<-signals
}
