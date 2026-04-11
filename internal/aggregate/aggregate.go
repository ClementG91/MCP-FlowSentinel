// Package aggregate accumulates raw PacketEvents into per-flow records and
// computes a suspicion score for each flow.
package aggregate

import (
	"context"
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/intel"
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

// privateNetworks holds all RFC 1918, loopback, and link-local ranges
// pre-parsed at init time for fast membership tests.
var privateNetworks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16",
		"::1/128", "fc00::/7", "fe80::/10",
	} {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			privateNetworks = append(privateNetworks, n)
		}
	}
}

// isPrivateIP reports whether ipStr is a loopback, link-local, or RFC 1918
// address that is not expected to have PTR records in public DNS.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true // unparseable — do not penalise
	}
	for _, n := range privateNetworks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

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
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	Protocol    string    `json:"protocol"`
	PacketCount int64     `json:"packet_count"`
	ByteCount   int64     `json:"byte_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	DurationMs  int64     `json:"duration_ms"`
	// Process fields
	PID         int32  `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	Cmdline     string `json:"cmdline,omitempty"`
	ParentPID   int32  `json:"parent_pid,omitempty"`
	ParentName  string `json:"parent_name,omitempty"`
	Username    string `json:"username,omitempty"`
	CreateTime  int64  `json:"create_time_ms,omitempty"`
	// Network intelligence
	ReverseDNS  string   `json:"reverse_dns,omitempty"`
	Country     string   `json:"country,omitempty"`
	ASNOrg      string   `json:"asn_org,omitempty"`
	GeoHighRisk bool     `json:"geo_high_risk,omitempty"`
	TLSSNIName  string   `json:"tls_sni,omitempty"`
	DNSQueries  []string `json:"dns_queries,omitempty"`
	// Analysis fields
	SuspicionScore   float64  `json:"suspicion_score"`
	RiskLevel        string   `json:"risk_level"`
	SuspicionReasons []string `json:"suspicion_reasons,omitempty"`
	CleanSignals     []string `json:"clean_signals,omitempty"`
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
	dnsQueries  map[string]struct{} // unique DNS query names observed for this flow
	tlsNames    map[string]struct{} // unique TLS SNI names observed for this flow
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
	DNSQuery   string // first question name from a DNS packet (optional)
	TLSSNIName string // server name from TLS ClientHello (optional)
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
	if pkt.DNSQuery != "" {
		if fs.dnsQueries == nil {
			fs.dnsQueries = make(map[string]struct{})
		}
		fs.dnsQueries[pkt.DNSQuery] = struct{}{}
	}
	if pkt.TLSSNIName != "" {
		if fs.tlsNames == nil {
			fs.tlsNames = make(map[string]struct{})
		}
		fs.tlsNames[pkt.TLSSNIName] = struct{}{}
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

		var dnsSlice []string
		for q := range fs.dnsQueries {
			dnsSlice = append(dnsSlice, q)
		}
		sort.Strings(dnsSlice)

		var sniSlice []string
		for n := range fs.tlsNames {
			sniSlice = append(sniSlice, n)
		}
		sniName := ""
		if len(sniSlice) > 0 {
			sort.Strings(sniSlice)
			sniName = sniSlice[0]
		}

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
			DNSQueries:  dnsSlice,
			TLSSNIName:  sniName,
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

	// ── Pass 2.5: GeoIP enrichment (synchronous, cached) ─────────────────────
	for i := range items {
		if gi := intel.Lookup(items[i].rec.DstIP); gi != nil {
			items[i].rec.Country = gi.CountryCode
			items[i].rec.ASNOrg = gi.OrgName
			items[i].rec.GeoHighRisk = gi.IsHighRisk
		}
	}

	// ── Pass 3: per-flow scoring ──────────────────────────────────────────────
	records := make([]FlowRecord, len(items))
	for i, it := range items {
		it.rec.SuspicionScore, it.rec.SuspicionReasons = score(it.key, it.rec, it.timestamps)
		it.rec.CleanSignals = computeCleanSignals(it.rec)
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

// suspiciousCmdlinePatterns match common attacker one-liners in process cmdlines.
// Regex allows catching whitespace variants that exact-string matching misses.
var suspiciousCmdlinePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bbase64\s+-[dD]\b`),
	regexp.MustCompile(`(?i)curl\s*\|\s*(?:ba)?sh`),
	regexp.MustCompile(`(?i)wget\s+.*\|\s*(?:ba)?sh`),
	regexp.MustCompile(`(?i)python[23]?\s+-c\b`),
	regexp.MustCompile(`(?i)(?:ba)?sh\s+-i\b`),
	regexp.MustCompile(`(?i)n(?:c|cat)\s+-e\b`),
	regexp.MustCompile(`/(?:tmp|dev/shm|var/tmp|run/shm)/`),
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
	// Skip the penalty for private/loopback IPs — they never have public PTR records.
	if rec.ReverseDNS == "" && !isPrivateIP(rec.DstIP) {
		add(0.8, "no reverse DNS — direct IP connection")
	}

	// DNS exfiltration: high-entropy subdomains indicate data encoding.
	for _, q := range rec.DNSQueries {
		if isHighEntropyDomain(q) {
			add(2.5, fmt.Sprintf("possible DNS exfiltration: high-entropy query %q", q))
			break // one penalty per flow
		}
	}

	// ── GeoIP / threat intelligence ─────────────────────────────────────────
	if rec.GeoHighRisk {
		add(1.5, fmt.Sprintf("destination in high-risk ASN: %s", rec.ASNOrg))
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
		for _, re := range suspiciousCmdlinePatterns {
			if re.MatchString(rec.Cmdline) {
				add(2.0, fmt.Sprintf("suspicious cmdline pattern %q in: %s", re.String(), rec.Cmdline))
				break
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
	if len(ts) < 3 {
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

// ─── DNS exfiltration detection ──────────────────────────────────────────────

// shannonEntropy computes the Shannon entropy (bits per character) of s.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	var h float64
	for _, cnt := range freq {
		p := float64(cnt) / n
		h -= p * math.Log2(p)
	}
	return h
}

// isHighEntropyDomain returns true when any subdomain label of fqdn looks
// like base64/hex-encoded data, which is a key indicator of DNS exfiltration.
// Thresholds: entropy > 3.5 bits/char OR label length > 40 chars.
func isHighEntropyDomain(fqdn string) bool {
	// Strip trailing dot if present.
	fqdn = strings.TrimSuffix(fqdn, ".")
	parts := strings.Split(fqdn, ".")
	// Ignore the public-suffix (TLD + registrable label).
	if len(parts) <= 2 {
		return false
	}
	for _, label := range parts[:len(parts)-2] {
		if len(label) == 0 {
			continue
		}
		if len(label) > 40 {
			return true
		}
		if shannonEntropy(label) > 3.5 {
			return true
		}
	}
	return false
}

// ─── Clean signals ────────────────────────────────────────────────────────────

// computeCleanSignals returns a list of human-readable explanations for why
// a flow looks benign. These are only populated when the suspicion score is
// low so the AI client can understand *why* a flow was not flagged.
func computeCleanSignals(rec FlowRecord) []string {
	if rec.SuspicionScore >= 2.0 {
		return nil // only annotate clearly low-risk flows
	}
	var signals []string
	if standardPorts[rec.DstPort] {
		switch rec.DstPort {
		case 443:
			signals = append(signals, "port 443 — standard HTTPS")
		case 80:
			signals = append(signals, "port 80 — standard HTTP")
		case 53:
			signals = append(signals, "port 53 — standard DNS")
		case 22:
			signals = append(signals, "port 22 — standard SSH")
		default:
			signals = append(signals, fmt.Sprintf("port %d is a standard protocol port", rec.DstPort))
		}
	}
	if rec.ReverseDNS != "" {
		signals = append(signals, fmt.Sprintf("resolves to %s", rec.ReverseDNS))
	}
	if rec.TLSSNIName != "" {
		signals = append(signals, fmt.Sprintf("TLS SNI: %s", rec.TLSSNIName))
	}
	if rec.Country != "" && !rec.GeoHighRisk {
		signals = append(signals, fmt.Sprintf("destination in %s (low-risk ASN)", rec.Country))
	}
	return signals
}
