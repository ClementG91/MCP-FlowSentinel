// Package aggregate accumulates raw PacketEvents into per-flow records and
// computes a suspicion score for each flow.
package aggregate

import (
	"context"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// dnsWorkers is the maximum number of concurrent reverse-DNS goroutines.
const dnsWorkers = 20

// dnsCacheTTL is how long a resolved (or negative) PTR result is reused.
const dnsCacheTTL = 5 * time.Minute

// dnsEntry is one cached PTR record.
type dnsEntry struct {
	hostname string
	expiry   time.Time
}

// dnsCache is the package-level reverse-DNS cache, persistent across tool calls.
// Key: IP string → value: dnsEntry. Negative results are also cached.
var dnsCache sync.Map

// ProcessSnapshot carries enriched process metadata from a single flow's owner.
// It is returned by ProcessResolver to avoid an import cycle between packages.
type ProcessSnapshot struct {
	PID        int32
	Name       string
	BinaryPath string
	Cmdline    string
	ParentPID  int32
	ParentName string
	Username   string
	CreateTime int64
}

// FlowKey is the canonical identifier for a unidirectional network flow.
// We group by destination to keep server-side listening processes visible.
type FlowKey struct {
	SrcIP   string
	DstIP   string
	DstPort uint16
	Proto   string // "TCP" | "UDP"
}

// FlowRecord is the final, enriched representation of a flow.
type FlowRecord struct {
	SrcIP            string    `json:"src_ip"`
	DstIP            string    `json:"dst_ip"`
	SrcPort          uint16    `json:"src_port"`
	DstPort          uint16    `json:"dst_port"`
	Protocol         string    `json:"protocol"`
	PacketCount      int64     `json:"packet_count"`
	ByteCount        int64     `json:"byte_count"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	DurationMs       int64     `json:"duration_ms"`
	// Process fields
	PID        int32  `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	Cmdline     string `json:"cmdline,omitempty"`
	ParentPID   int32  `json:"parent_pid,omitempty"`
	ParentName  string `json:"parent_name,omitempty"`
	Username    string `json:"username,omitempty"`
	CreateTime  int64  `json:"create_time_ms,omitempty"`
	// Analysis fields
	ReverseDNS       string   `json:"reverse_dns,omitempty"`
	SuspicionScore   float64  `json:"suspicion_score"`
	RiskLevel        string   `json:"risk_level"`
	SuspicionReasons []string `json:"suspicion_reasons,omitempty"`
}

// ProcessResolver maps a packet four-tuple to the process that owns it.
// Returning a pointer avoids import cycles; nil means no process identified.
type ProcessResolver func(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) *ProcessSnapshot

// flowState is the mutable, concurrent-safe per-flow accumulator.
type flowState struct {
	mu          sync.Mutex
	srcPort     uint16
	packetCount int64
	byteCount   int64
	firstSeen   time.Time
	lastSeen    time.Time
	timestamps  []time.Time
}

// Aggregator accumulates PacketEvents into flow states using a sync.Map
// for lock-free concurrent writes across goroutines.
type Aggregator struct {
	flows sync.Map // FlowKey → *flowState
}

// PacketEvent mirrors capture.PacketEvent but uses net.IP to avoid an
// import cycle between aggregate and capture.
type PacketEvent struct {
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	Proto      string
	PayloadLen uint32
	Timestamp  time.Time
}

// Add processes a single packet event.
func (a *Aggregator) Add(pkt PacketEvent) {
	key := FlowKey{
		SrcIP:   pkt.SrcIP.String(),
		DstIP:   pkt.DstIP.String(),
		DstPort: pkt.DstPort,
		Proto:   pkt.Proto,
	}

	v, _ := a.flows.LoadOrStore(key, &flowState{
		firstSeen: pkt.Timestamp,
		srcPort:   pkt.SrcPort,
	})
	fs := v.(*flowState)

	fs.mu.Lock()
	fs.packetCount++
	fs.byteCount += int64(pkt.PayloadLen)
	if pkt.Timestamp.After(fs.lastSeen) {
		fs.lastSeen = pkt.Timestamp
	}
	if len(fs.timestamps) < 1024 { // cap to avoid unbounded memory
		fs.timestamps = append(fs.timestamps, pkt.Timestamp)
	}
	fs.mu.Unlock()
}

// Finalize converts all accumulated flow states into scored FlowRecords.
// resolver may be nil (process info is skipped).
// Records are sorted by SuspicionScore descending (highest risk first).
func (a *Aggregator) Finalize(resolver ProcessResolver) []FlowRecord {
	// ── Pass 1: collect base records and per-flow timestamps ─────────────────
	type interim struct {
		rec        FlowRecord
		key        FlowKey
		timestamps []time.Time
	}
	var items []interim

	a.flows.Range(func(k, v any) bool {
		key := k.(FlowKey)
		fs := v.(*flowState)

		fs.mu.Lock()
		tsCopy := make([]time.Time, len(fs.timestamps))
		copy(tsCopy, fs.timestamps)
		rec := FlowRecord{
			SrcIP:       key.SrcIP,
			DstIP:       key.DstIP,
			SrcPort:     fs.srcPort,
			DstPort:     key.DstPort,
			Protocol:    key.Proto,
			PacketCount: fs.packetCount,
			ByteCount:   fs.byteCount,
			FirstSeen:   fs.firstSeen,
			LastSeen:    fs.lastSeen,
		}
		fs.mu.Unlock()

		if !rec.LastSeen.IsZero() && !rec.FirstSeen.IsZero() {
			rec.DurationMs = rec.LastSeen.Sub(rec.FirstSeen).Milliseconds()
		}
		if resolver != nil {
			if snap := resolver(rec.SrcIP, rec.SrcPort, rec.DstIP, rec.DstPort, rec.Protocol); snap != nil {
				rec.PID         = snap.PID
				rec.ProcessName = snap.Name
				rec.BinaryPath  = snap.BinaryPath
				rec.Cmdline     = snap.Cmdline
				rec.ParentPID   = snap.ParentPID
				rec.ParentName  = snap.ParentName
				rec.Username    = snap.Username
				rec.CreateTime  = snap.CreateTime
			}
		}
		items = append(items, interim{rec: rec, key: key, timestamps: tsCopy})
		return true
	})

	// ── Pass 2: parallel reverse-DNS (semaphore-bounded) ─────────────────────
	sem := make(chan struct{}, dnsWorkers)
	var wg sync.WaitGroup
	for i := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			items[idx].rec.ReverseDNS = lookupReverseDNS(items[idx].rec.DstIP)
		}(i)
	}
	wg.Wait()

	// ── Pass 3: per-flow scoring ──────────────────────────────────────────────
	records := make([]FlowRecord, len(items))
	for i, it := range items {
		it.rec.SuspicionScore, it.rec.SuspicionReasons = score(it.key, it.rec, it.timestamps)
		it.rec.RiskLevel = riskLabel(it.rec.SuspicionScore)
		records[i] = it.rec
	}

	// ── Pass 4: cross-flow scan detection ────────────────────────────────────
	dstsBySrc := make(map[string]map[string]struct{}, 16)
	for _, rec := range records {
		if dstsBySrc[rec.SrcIP] == nil {
			dstsBySrc[rec.SrcIP] = make(map[string]struct{})
		}
		dstsBySrc[rec.SrcIP][rec.DstIP] = struct{}{}
	}
	for i := range records {
		n := len(dstsBySrc[records[i].SrcIP])
		var bonus float64
		var reason string
		switch {
		case n >= 20:
			bonus = 3.0
			reason = fmt.Sprintf("scan pattern: %d unique destinations from same source", n)
		case n >= 8:
			bonus = 1.5
			reason = fmt.Sprintf("possible scan: %d unique destinations from same source", n)
		}
		if bonus > 0 {
			records[i].SuspicionScore = min(10.0, records[i].SuspicionScore+bonus)
			records[i].SuspicionReasons = append(records[i].SuspicionReasons, reason)
			records[i].RiskLevel = riskLabel(records[i].SuspicionScore)
		}
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].SuspicionScore > records[j].SuspicionScore
	})
	return records
}

// ─── Scoring ──────────────────────────────────────────────────────────────────

// knownBadPorts maps destination port → reason string.
var knownBadPorts = map[uint16]string{
	4444:  "Metasploit default listener",
	1337:  "common C2/leet port",
	31337: "Back Orifice",
	6666:  "IRC/botnet",
	6667:  "IRC/botnet",
	6668:  "IRC/botnet",
	6669:  "IRC/botnet",
	9001:  "Tor relay",
	9030:  "Tor directory authority",
	9150:  "Tor Browser SOCKS",
	1080:  "SOCKS proxy",
	4899:  "Radmin backdoor",
	5554:  "Sasser worm",
	9999:  "common C2",
	7777:  "common C2",
	65535: "max port / evasion",
}

// standardPorts are widely used legitimate ports that reduce suspicion.
var standardPorts = map[uint16]bool{
	20: true, 21: true, 22: true, 25: true, 53: true,
	80: true, 110: true, 123: true, 143: true, 161: true,
	162: true, 389: true, 443: true, 465: true, 587: true,
	636: true, 993: true, 995: true, 3306: true, 5432: true,
	6379: true, 8080: true, 8443: true, 27017: true,
}

// suspiciousPathPrefixes are binary locations that indicate an implant.
var suspiciousPathPrefixes = []string{
	"/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/",
	`\AppData\Local\Temp\`, `\Windows\Temp\`, `C:\Temp\`,
}

// suspiciousCmdlineKeywords trigger extra scoring when found in a process cmdline.
var suspiciousCmdlineKeywords = []string{
	"/tmp/", "/dev/shm/",
	"base64 -d", "base64 -D",
	"curl | sh", "curl|sh", "wget -O- |", "wget -qO- |",
	"python -c", "python3 -c",
	"bash -i", "sh -i",
	"nc -e", "ncat -e",
}

func score(key FlowKey, rec FlowRecord, ts []time.Time) (float64, []string) {
	var total float64
	var reasons []string

	add := func(pts float64, reason string) {
		total += pts
		reasons = append(reasons, reason)
	}

	// ── Port analysis ───────────────────────────────────────────────────────
	// Skip scoring for IANA dynamic/ephemeral ports (49152–65535).
	if why, bad := knownBadPorts[key.DstPort]; bad {
		add(4.0, fmt.Sprintf("known high-risk port %d (%s)", key.DstPort, why))
	} else if key.DstPort < 49152 && !standardPorts[key.DstPort] {
		add(1.0, fmt.Sprintf("non-standard port %d", key.DstPort))
	}

	// ── DNS analysis ────────────────────────────────────────────────────────
	if rec.ReverseDNS == "" {
		add(0.8, "no reverse DNS — direct IP connection")
	}

	// ── Process / binary analysis ───────────────────────────────────────────
	if rec.PID > 0 && rec.BinaryPath == "" {
		add(1.0, "could not resolve binary path for PID")
	}
	for _, prefix := range suspiciousPathPrefixes {
		if strings.Contains(rec.BinaryPath, prefix) {
			add(2.5, fmt.Sprintf("binary running from suspicious path: %s", rec.BinaryPath))
			break
		}
	}

	// ── Cmdline analysis ────────────────────────────────────────────────────
	if rec.Cmdline != "" {
		for _, kw := range suspiciousCmdlineKeywords {
			if strings.Contains(rec.Cmdline, kw) {
				add(2.0, fmt.Sprintf("suspicious cmdline keyword %q in: %s", kw, rec.Cmdline))
				break // one reason per flow is enough
			}
		}
	}

	// ── Beaconing detection ─────────────────────────────────────────────────
	if bs, reason := beaconingScore(ts); bs > 0 {
		add(bs, reason)
	}

	// ── High data volume ────────────────────────────────────────────────────
	if rec.ByteCount > 5*1024*1024 {
		add(0.5, fmt.Sprintf("high data transfer: %.1f MB", float64(rec.ByteCount)/1024/1024))
	}

	if total > 10.0 {
		total = 10.0
	}
	return total, reasons
}

// beaconingScore computes a score contribution based on inter-arrival
// time regularity. Low coefficient-of-variation → beaconing.
func beaconingScore(ts []time.Time) (float64, string) {
	if len(ts) < 5 {
		return 0, ""
	}
	iats := make([]float64, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		iats[i-1] = float64(ts[i].Sub(ts[i-1]).Milliseconds())
	}
	var sum float64
	for _, v := range iats {
		sum += v
	}
	mean := sum / float64(len(iats))
	if mean < 1 {
		return 0, ""
	}
	var variance float64
	for _, v := range iats {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(iats))
	cv := math.Sqrt(variance) / mean

	switch {
	case cv < 0.15:
		return 3.5, fmt.Sprintf("strong beaconing pattern (interval CV=%.2f, mean=%.0f ms)", cv, mean)
	case cv < 0.30:
		return 2.0, fmt.Sprintf("possible beaconing (interval CV=%.2f, mean=%.0f ms)", cv, mean)
	default:
		return 0, ""
	}
}

// riskLabel converts a numeric score to a human-readable risk tier.
func riskLabel(score float64) string {
	switch {
	case score >= 7.0:
		return "CRITICAL"
	case score >= 5.0:
		return "HIGH"
	case score >= 2.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// lookupReverseDNS returns the PTR hostname for ip, using a package-level
// TTL cache to avoid redundant DNS queries across repeated tool calls.
func lookupReverseDNS(ip string) string {
	now := time.Now()
	if v, ok := dnsCache.Load(ip); ok {
		e := v.(dnsEntry)
		if now.Before(e.expiry) {
			return e.hostname
		}
	}
	hostname := doLookupReverseDNS(ip)
	dnsCache.Store(ip, dnsEntry{hostname: hostname, expiry: now.Add(dnsCacheTTL)})
	return hostname
}

// doLookupReverseDNS performs the actual PTR query with a 200 ms deadline.
func doLookupReverseDNS(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	r := &net.Resolver{}
	names, err := r.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
