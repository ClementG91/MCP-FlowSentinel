package alerting

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
)

// AlertRecord is one fired alert, persisted in the alert log.
type AlertRecord struct {
	Timestamp time.Time              `json:"timestamp"`
	Severity  string                 `json:"severity"`   // CRITICAL, HIGH, etc.
	DedupeKey string                 `json:"dedupe_key"` // flow identifier
	Flow      aggregate.FlowRecord   `json:"flow"`
}

// AlertQueryOpts filters alert log reads.
type AlertQueryOpts struct {
	MaxAgeHours int     // 0 → default 24 h
	MinScore    float64 // 0 → all scores
	TopN        int     // 0 → no limit
}

var (
	alertLogMu   sync.Mutex
	alertLogPath string
)

func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	dir := filepath.Join(home, ".cache", "mcp-flowsentinel")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		dir = os.TempDir()
	}
	alertLogPath = filepath.Join(dir, "alerts.jsonl")
}

// AlertLogPath returns the absolute path of the alert log file.
func AlertLogPath() string { return alertLogPath }

// writeAlertRecord appends one AlertRecord to the alert log (best-effort).
func writeAlertRecord(rec AlertRecord) {
	data, err := json.Marshal(rec)
	if err != nil {
		log.Printf("alerting: marshal alert record: %v", err)
		return
	}

	alertLogMu.Lock()
	defer alertLogMu.Unlock()

	f, err := os.OpenFile(alertLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("alerting: open alert log: %v", err)
		return
	}
	if _, err := f.WriteString(string(data) + "\n"); err != nil {
		log.Printf("alerting: write alert log: %v", err)
	}
	f.Close()
}

// GetAlerts reads recent alerts from the alert log.
func GetAlerts(opts AlertQueryOpts) ([]AlertRecord, error) {
	maxAge := time.Duration(opts.MaxAgeHours) * time.Hour
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	cutoff := time.Now().Add(-maxAge)

	alertLogMu.Lock()
	defer alertLogMu.Unlock()

	f, err := os.Open(alertLogPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []AlertRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 2*1024*1024), 2*1024*1024)

	for scanner.Scan() {
		var rec AlertRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Timestamp.Before(cutoff) {
			continue
		}
		if opts.MinScore > 0 && rec.Flow.SuspicionScore < opts.MinScore {
			continue
		}
		results = append(results, rec)
	}

	if err := scanner.Err(); err != nil {
		return results, err
	}

	// Most recent first.
	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}

	if opts.TopN > 0 && len(results) > opts.TopN {
		results = results[:opts.TopN]
	}
	return results, nil
}

// SetAlertLogPathForTesting overrides the alert log path. Only for tests.
func SetAlertLogPathForTesting(path string) {
	alertLogMu.Lock()
	defer alertLogMu.Unlock()
	alertLogPath = path
}
