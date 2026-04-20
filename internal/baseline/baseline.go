// Package baseline provides per-(process, port) behavioural baselines using
// Welford's online algorithm for computing running mean and variance without
// storing individual samples.
//
// Usage:
//
//	baseline.Init(cacheDir)                    // once at startup
//	m := baseline.AnomalyMultiplier(name, port, bytes)  // in score()
//	baseline.Observe(name, port, bytes)        // after each window
package baseline

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─── Internal state ───────────────────────────────────────────────────────────

// entry holds Welford online statistics for a single (processName, dstPort) key.
// The statistics track byte counts per flow over successive observation windows.
type entry struct {
	N        int64     `json:"n"`          // number of observations
	MeanB    float64   `json:"mean_bytes"` // running mean of bytes
	M2B      float64   `json:"m2_bytes"`   // sum of squared deviations (Welford M2)
	LastSeen time.Time `json:"last_seen"`
}

// welfordUpdate applies one Welford step to (n, mean, M2) and returns updated values.
// See Knuth TAOCP Vol 2, §4.2.2.
func (e *entry) observe(x float64) {
	e.N++
	delta := x - e.MeanB
	e.MeanB += delta / float64(e.N)
	delta2 := x - e.MeanB
	e.M2B += delta * delta2
}

// stddev returns the sample standard deviation (0 when N < 2).
func (e *entry) stddev() float64 {
	if e.N < 2 {
		return 0
	}
	return math.Sqrt(e.M2B / float64(e.N-1))
}

// zScore returns the Z-score for value x. Returns 0 when stddev is 0.
func (e *entry) zScore(x float64) float64 {
	sd := e.stddev()
	if sd == 0 {
		return 0
	}
	return (x - e.MeanB) / sd
}

// stale returns true if this entry has not been updated in > stalePeriod.
const stalePeriod = 72 * time.Hour

func (e *entry) stale() bool {
	return !e.LastSeen.IsZero() && time.Since(e.LastSeen) > stalePeriod
}

// minObservations is the minimum number of samples before the multiplier is
// anything other than neutral (1.0). Below this threshold there is not enough
// data to distinguish anomaly from noise.
const minObservations = 5

// ─── Store ────────────────────────────────────────────────────────────────────

// store is the in-memory baseline database.
type store struct {
	mu       sync.RWMutex
	entries  map[string]*entry
	cacheDir string
}

var global = &store{
	entries: make(map[string]*entry),
}

// makeKey returns the canonical lookup key for (process, port).
func makeKey(processName string, dstPort uint16) string {
	return strings.ToLower(processName) + ":" + portStr(dstPort)
}

// portStr converts a uint16 to string without fmt overhead.
func portStr(p uint16) string {
	b := [5]byte{}
	n := 0
	if p == 0 {
		return "0"
	}
	tmp := p
	for tmp > 0 {
		b[n] = byte('0' + tmp%10)
		n++
		tmp /= 10
	}
	// reverse
	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b[:n])
}

// ─── Public API ───────────────────────────────────────────────────────────────

// Init initialises the global store, loading any previously persisted data from
// cacheDir. Safe to call multiple times (subsequent calls reload from disk).
// cacheDir is typically ~/.cache/mcp-flowsentinel/.
func Init(cacheDir string) {
	global.mu.Lock()
	global.cacheDir = cacheDir
	global.mu.Unlock()
	load()
}

// Observe records one observation for the given (processName, dstPort) key.
// bytes is the byte count transferred in the flow. Call this once per scored
// flow, after the final risk score has been assigned to a FlowRecord.
func Observe(processName string, dstPort uint16, bytes int64) {
	if processName == "" {
		return
	}
	key := makeKey(processName, dstPort)
	x := float64(bytes)

	global.mu.Lock()
	e, ok := global.entries[key]
	if !ok {
		e = &entry{}
		global.entries[key] = e
	}
	e.observe(x)
	e.LastSeen = time.Now()
	global.mu.Unlock()
}

// AnomalyMultiplier returns a score multiplier based on how anomalous bytes is
// relative to the historical baseline for (processName, dstPort).
//
// Multiplier table:
//
//	N < minObservations : 1.0  (no baseline yet)
//	Z  <  1σ            : 0.7  (within normal — dampen minor signals)
//	1σ ≤ Z  <  2σ       : 1.0  (normal variation — no change)
//	2σ ≤ Z  <  3σ       : 1.3  (elevated — slightly amplify)
//	Z  ≥  3σ            : 1.8  (anomalous — significantly amplify)
func AnomalyMultiplier(processName string, dstPort uint16, bytes int64) float64 {
	if processName == "" {
		return 1.0
	}
	key := makeKey(processName, dstPort)

	global.mu.RLock()
	e, ok := global.entries[key]
	if !ok || e.N < minObservations {
		global.mu.RUnlock()
		return 1.0
	}
	z := math.Abs(e.zScore(float64(bytes)))
	global.mu.RUnlock()

	switch {
	case z >= 3.0:
		return 1.8
	case z >= 2.0:
		return 1.3
	case z >= 1.0:
		return 1.0
	default:
		return 0.7
	}
}

// Prune removes entries that have not been observed in more than stalePeriod.
// It is called automatically during Persist but can also be called manually.
func Prune() {
	global.mu.Lock()
	defer global.mu.Unlock()
	for k, e := range global.entries {
		if e.stale() {
			delete(global.entries, k)
		}
	}
}

// Size returns the number of tracked (process, port) baselines.
func Size() int {
	global.mu.RLock()
	defer global.mu.RUnlock()
	return len(global.entries)
}

// ─── Persistence ──────────────────────────────────────────────────────────────

func cachePath() string {
	global.mu.RLock()
	dir := global.cacheDir
	global.mu.RUnlock()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "baseline.json")
}

// Persist flushes the current in-memory state to disk (atomic write via rename).
// Stale entries are pruned before writing. A missing cacheDir is silently ignored.
func Persist() error {
	Prune()

	path := cachePath()
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	global.mu.RLock()
	data, err := json.Marshal(global.entries)
	global.mu.RUnlock()
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// load reads persisted state from disk into the global store.
func load() {
	path := cachePath()
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return // file absent or unreadable — start fresh
	}
	var loaded map[string]*entry
	if err := json.Unmarshal(data, &loaded); err != nil {
		return // corrupt file — start fresh
	}

	global.mu.Lock()
	for k, e := range loaded {
		if !e.stale() {
			global.entries[k] = e
		}
	}
	global.mu.Unlock()
}
