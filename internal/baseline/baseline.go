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
type entry struct {
	N        int64     `json:"n"`
	MeanB    float64   `json:"mean_bytes"`
	M2B      float64   `json:"m2_bytes"`
	LastSeen time.Time `json:"last_seen"`
}

func (e *entry) observe(x float64) {
	e.N++
	delta := x - e.MeanB
	e.MeanB += delta / float64(e.N)
	delta2 := x - e.MeanB
	e.M2B += delta * delta2
}

func (e *entry) stddev() float64 {
	if e.N < 2 {
		return 0
	}
	return math.Sqrt(e.M2B / float64(e.N-1))
}

func (e *entry) zScore(x float64) float64 {
	sd := e.stddev()
	if sd == 0 {
		return 0
	}
	return (x - e.MeanB) / sd
}

const stalePeriod = 72 * time.Hour

func (e *entry) stale() bool {
	return !e.LastSeen.IsZero() && time.Since(e.LastSeen) > stalePeriod
}

const minObservations = 5

// ─── Destination tracking ─────────────────────────────────────────────────────

// maxDests is the maximum number of destination IPs tracked per process.
// Beyond this the set is full and new IPs are counted but not remembered.
const maxDests = 2000

// minDestObs is the minimum total connections before IsNewDestination is
// meaningful. Below this we don't have enough data to flag new destinations.
const minDestObs = 5

// destEntry tracks the set of destination IPs a process has connected to.
type destEntry struct {
	Seen  map[string]bool `json:"seen"`
	Count int             `json:"count"` // total connections (including overflow)
}

// ─── Beaconing tracking ───────────────────────────────────────────────────────

// minBeaconingObs is the number of beaconing detections after which a process
// is classified as an "expected beaconer" and the signal is suppressed.
const minBeaconingObs = 10

// beaconEntry counts how many capture windows triggered beaconing scoring
// for a given process name.
type beaconEntry struct {
	Count int `json:"count"`
}

// ─── Store ────────────────────────────────────────────────────────────────────

// store is the in-memory baseline database.
type store struct {
	mu        sync.RWMutex
	entries   map[string]*entry       // key: "processName:port"
	dests     map[string]*destEntry   // key: processName (lowercase)
	beaconing map[string]*beaconEntry // key: processName (lowercase)
	cacheDir  string
}

var global = &store{
	entries:   make(map[string]*entry),
	dests:     make(map[string]*destEntry),
	beaconing: make(map[string]*beaconEntry),
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
	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b[:n])
}

// ─── Public API ───────────────────────────────────────────────────────────────

// Init initialises the global store, loading any previously persisted data from
// cacheDir. Safe to call multiple times (subsequent calls reload from disk).
func Init(cacheDir string) {
	global.mu.Lock()
	global.cacheDir = cacheDir
	global.mu.Unlock()
	load()
}

// Observe records one observation for the given (processName, dstPort) key.
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

// ObserveDest records that processName connected to dstIP.
// Call this after Finalize() for each scored flow.
func ObserveDest(processName, dstIP string) {
	if processName == "" || dstIP == "" {
		return
	}
	proc := strings.ToLower(processName)

	global.mu.Lock()
	de, ok := global.dests[proc]
	if !ok {
		de = &destEntry{Seen: make(map[string]bool)}
		global.dests[proc] = de
	}
	de.Count++
	if !de.Seen[dstIP] && len(de.Seen) < maxDests {
		de.Seen[dstIP] = true
	}
	global.mu.Unlock()
}

// IsNewDestination returns (isNew=true, confident=true) when the process has
// been observed at least minDestObs times and dstIP has never been seen for it.
// Returns (false, false) on cold start (< minDestObs observations).
func IsNewDestination(processName, dstIP string) (isNew bool, confident bool) {
	if processName == "" || dstIP == "" {
		return false, false
	}
	proc := strings.ToLower(processName)

	global.mu.RLock()
	de, ok := global.dests[proc]
	if !ok || de.Count < minDestObs {
		global.mu.RUnlock()
		return false, false
	}
	seen := de.Seen[dstIP]
	global.mu.RUnlock()

	return !seen, true
}

// ObserveBeaconing records that processName triggered beaconing scoring.
// After minBeaconingObs observations the process becomes an expected beaconer.
func ObserveBeaconing(processName string) {
	if processName == "" {
		return
	}
	proc := strings.ToLower(processName)

	global.mu.Lock()
	be, ok := global.beaconing[proc]
	if !ok {
		be = &beaconEntry{}
		global.beaconing[proc] = be
	}
	be.Count++
	global.mu.Unlock()
}

// IsExpectedBeaconer returns true when processName has triggered beaconing in
// at least minBeaconingObs capture windows. These processes exhibit regular
// heartbeats as normal behaviour and should have the signal suppressed.
func IsExpectedBeaconer(processName string) bool {
	if processName == "" {
		return false
	}
	proc := strings.ToLower(processName)

	global.mu.RLock()
	be, ok := global.beaconing[proc]
	if !ok {
		global.mu.RUnlock()
		return false
	}
	count := be.Count
	global.mu.RUnlock()

	return count >= minBeaconingObs
}

// AnomalyMultiplier returns a score multiplier based on how anomalous bytes is
// relative to the historical baseline for (processName, dstPort).
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

// MinDestObs returns the minimum observations threshold for IsNewDestination.
// Exported for testing only.
func MinDestObs() int { return minDestObs }

// MinBeaconingObs returns the beaconing observation threshold.
// Exported for testing only.
func MinBeaconingObs() int { return minBeaconingObs }

// ─── Persistence ──────────────────────────────────────────────────────────────

// persistData is the on-disk representation of the full baseline state.
// The "entries" key distinguishes new format from the legacy map[string]*entry.
type persistData struct {
	Entries   map[string]*entry       `json:"entries"`
	Dests     map[string]*destEntry   `json:"dests,omitempty"`
	Beaconing map[string]*beaconEntry `json:"beaconing,omitempty"`
}

func cachePath() string {
	global.mu.RLock()
	dir := global.cacheDir
	global.mu.RUnlock()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "baseline.json")
}

// Persist flushes current state to disk (atomic write via rename).
// Stale entries are pruned before writing.
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
	data, err := json.Marshal(persistData{
		Entries:   global.entries,
		Dests:     global.dests,
		Beaconing: global.beaconing,
	})
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
		return
	}

	// Try new format first: {"entries": {...}, "dests": {...}, "beaconing": {...}}.
	var pd persistData
	if json.Unmarshal(data, &pd) == nil && pd.Entries != nil {
		global.mu.Lock()
		for k, e := range pd.Entries {
			if !e.stale() {
				global.entries[k] = e
			}
		}
		if pd.Dests != nil {
			global.dests = pd.Dests
		}
		if pd.Beaconing != nil {
			global.beaconing = pd.Beaconing
		}
		global.mu.Unlock()
		return
	}

	// Fall back to legacy format: raw map[string]*entry.
	var legacy map[string]*entry
	if json.Unmarshal(data, &legacy) == nil {
		global.mu.Lock()
		for k, e := range legacy {
			if !e.stale() {
				global.entries[k] = e
			}
		}
		global.mu.Unlock()
	}
}
