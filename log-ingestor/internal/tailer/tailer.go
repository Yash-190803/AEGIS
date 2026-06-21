package tailer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const pollInterval = 200 * time.Millisecond

// LogLine is a normalized log event emitted by the tailer.
type LogLine struct {
	Timestamp  time.Time `json:"timestamp"`
	FilePath   string    `json:"filePath"`
	LogType    string    `json:"logType"`
	LineNumber int64     `json:"lineNumber"`
	Content    string    `json:"content"`
}

// TailFile opens a file, seeks to the end, then continuously reads newly appended lines.
// It reopens the path when the file is deleted, recreated, replaced, or truncated, which
// allows normal log rotation to continue without restarting the ingestor.
//
// The function blocks until ctx is cancelled or an unrecoverable initial open error occurs.
// New lines are sent to out with inferred log type and monotonically increasing line number.
//
// @param ctx Context used to stop the tailer gracefully.
// @param filePath Path to the log file to follow.
// @param out Channel that receives normalized log lines.
// @returns nil on graceful shutdown, or an error for invalid arguments or initial open failure.
func TailFile(ctx context.Context, filePath string, out chan<- LogLine) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	if out == nil {
		return errors.New("output channel is required")
	}
	cleanPath := filepath.Clean(filePath)
	file, reader, lineNumber, err := openAtEnd(cleanPath)
	if err != nil {
		return fmt.Errorf("start tailing %s: %w", cleanPath, err)
	}
	defer file.Close()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		if err := readAvailable(ctx, cleanPath, reader, &lineNumber, out); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			file.Close()
			file, reader, lineNumber, err = waitAndOpen(ctx, cleanPath)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			}
			continue
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		reopen, err := needsReopen(file, cleanPath)
		if err != nil {
			return err
		}
		if reopen {
			file.Close()
			file, reader, lineNumber, err = waitAndOpen(ctx, cleanPath)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			}
		}
	}
}

func openAtEnd(path string) (*os.File, *bufio.Reader, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, 0, err
	}
	lineCount, err := countExistingLines(file)
	if err != nil {
		file.Close()
		return nil, nil, 0, err
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		file.Close()
		return nil, nil, 0, fmt.Errorf("seek %s to end: %w", path, err)
	}
	return file, bufio.NewReader(file), lineCount, nil
}

func countExistingLines(file *os.File) (int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	reader := bufio.NewReader(file)
	var count int64
	for {
		segment, err := reader.ReadString('\n')
		if len(segment) > 0 {
			count++
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		return count, err
	}
}

func readAvailable(ctx context.Context, path string, reader *bufio.Reader, lineNumber *int64, out chan<- LogLine) error {
	for {
		rawLine, err := reader.ReadString('\n')
		if len(rawLine) > 0 {
			*lineNumber = *lineNumber + 1
			entry := LogLine{
				Timestamp:  time.Now().UTC(),
				FilePath:   path,
				LogType:    inferLogType(path),
				LineNumber: *lineNumber,
				Content:    strings.TrimRight(rawLine, "\r\n"),
			}
			select {
			case out <- entry:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
}

func waitAndOpen(ctx context.Context, path string) (*os.File, *bufio.Reader, int64, error) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		file, reader, lineNumber, err := openAtEnd(path)
		if err == nil {
			return file, reader, lineNumber, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

func needsReopen(file *os.File, path string) (bool, error) {
	pathInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	openInfo, err := file.Stat()
	if err != nil {
		return true, nil
	}
	offset, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return true, nil
	}
	return !os.SameFile(pathInfo, openInfo) || pathInfo.Size() < offset, nil
}

func inferLogType(filePath string) string {
	name := strings.ToLower(filepath.Base(filePath))
	switch {
	case strings.Contains(name, "auth"):
		return "AUTH"
	case strings.Contains(name, "network"):
		return "NETWORK"
	case strings.Contains(name, "system"):
		return "SYSTEM"
	default:
		return "APPLICATION"
	}
}
