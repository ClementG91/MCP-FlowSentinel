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

	"github.com/ClementG91/MCP-FlowSentinel/internal/cache"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
	"github.com/ClementG91/MCP-FlowSentinel/internal/intel"
	"github.com/ClementG91/MCP-FlowSentinel/internal/ja3"
)

// dnsCache is the package-level reverse-DNS LRU cache, bounded at 10 000 entries.
// Key: IP string → hostname string ("" for negative results).
// Entries expire after getDNSCacheTTL(); the LRU evicts oldest entries at capacity.
var dnsCache = cache.New[string, string](10_000)

// getDNSCacheTTL returns the configured DNS cache TTL, falling back to 5 minutes.
func getDNSCacheTTL() time.Duration {
	ttl := config.Get().Capture.DNSCacheTTLSec
	if ttl <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(ttl) * time.Second
}

// privateNetworks holds all RFC 1918, loopback, and link-local ranges
// pre-parsed at init time for fast membership tests.
var privateNetworks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16",
		"100.64.0.0/10", // RFC 6598 carrier-grade NAT
		"::1/128",       // IPv6 loopback
		"fc00::/7",      // IPv6 unique local (ULA)
		"fe80::/10",     // IPv6 link-local
		"100::/64",      // IPv6 discard prefix (RFC 6666)
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

// dohProviders are well-known DNS-over-HTTPS provider hostnames.
// Traffic to these on standard HTTPS ports may indicate DNS tunneling or
// covert channel use by processes that have no business performing DoH.
var dohProviders = map[string]bool{
	"dns.google":                 true,
	"cloudflare-dns.com":         true,
	"1dot1dot1dot1.cloudflare-dns.com": true,
	"dns.quad9.net":              true,
	"dns9.quad9.net":             true,
	"doh.opendns.com":            true,
	"dns.nextdns.io":             true,
	"doh.cleanbrowsing.org":      true,
	"doh.xfinity.com":            true,
	"mozilla.cloudflare-dns.com": true,
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
	// JA3 TLS fingerprinting
	JA3Hash     string `json:"ja3_hash,omitempty"`     // MD5 of TLS ClientHello parameters
	JA3KnownBad string `json:"ja3_known_bad,omitempty"` // malware family if hash matches known-bad list
	// QUIC / transport enrichment
	IsQUIC bool `json:"is_quic,omitempty"` // true when at least one QUIC Initial packet was observed
	// DNS response analysis
	NXDomainCount int    `json:"nxdomain_count,omitempty"` // number of NXDOMAIN responses in this flow
	MinDNSTTL     uint32 `json:"min_dns_ttl,omitempty"`    // minimum A/AAAA TTL observed (0 = no answers)
	// Analysis fields
	SuspicionScore   float64  `json:"suspicion_score"`
	RiskLevel        string   `json:"risk_level"`
	SuspicionReasons []string `json:"suspicion_reasons,omitempty"`
	// MITRE ATT&CK techniques matched by the detection reasons (deduplicated).
	MITRETechniques []intel.MITRETechnique `json:"mitre_techniques,omitempty"`
	CleanSignals    []string               `json:"clean_signals,omitempty"`
	// Interface is the capture interface this flow was observed on (daemon mode only).
	Interface string `json:"interface,omitempty"`
}

// ProcessResolver maps a packet four-tuple to the process that owns it.
// Returning a pointer avoids import cycles; nil means no process identified.
type ProcessResolver func(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) *ProcessSnapshot

// flowState is the mutable, concurrent-safe per-flow accumulator.
type flowState struct {
	mu            sync.Mutex
	srcPort       uint16
	packetCount   int64
	byteCount     int64
	firstSeen     time.Time
	lastSeen      time.Time
	timestamps    []time.Time
	dnsQueries    map[string]struct{} // unique DNS query names observed for this flow
	tlsNames      map[string]struct{} // unique TLS SNI names observed for this flow
	ja3Hash       string              // first JA3 fingerprint observed for this flow
	isQUIC        bool                // any packet in this flow was a QUIC Initial
	nxdomainCount int                 // number of NXDOMAIN responses in this flow
	minDNSTTL     uint32              // minimum A/AAAA TTL from DNS responses; 0 = not seen
}

// Aggregator accumulates PacketEvents into flow states using a sync.Map
// for lock-free concurrent writes across goroutines.
type Aggregator struct {
	flows sync.Map // FlowKey → *flowState
}

// PacketEvent mirrors capture.PacketEvent but uses net.IP to avoid an
// import cycle between aggregate and capture.
type PacketEvent struct {
	SrcIP         net.IP
	DstIP         net.IP
	SrcPort       uint16
	DstPort       uint16
	Proto         string
	PayloadLen    uint32
	Timestamp     time.Time
	DNSQuery      string // first question name from a DNS packet (optional)
	TLSSNIName    string // server name from TLS ClientHello (optional)
	JA3Hash       string // JA3 fingerprint of TLS ClientHello (optional)
	IsQUIC        bool   // true when UDP 443 payload is a QUIC Initial packet
	DNSNXDomain   bool   // DNS response returned NXDOMAIN
	DNSMinRespTTL uint32 // minimum A/AAAA TTL from DNS response (0 = no answers)
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
	if pkt.JA3Hash != "" && fs.ja3Hash == "" {
		fs.ja3Hash = pkt.JA3Hash // keep only the first seen ClientHello per flow
	}
	if pkt.IsQUIC {
		fs.isQUIC = true
	}
	if pkt.DNSNXDomain {
		fs.nxdomainCount++
	}
	if pkt.DNSMinRespTTL > 0 {
		if fs.minDNSTTL == 0 || pkt.DNSMinRespTTL < fs.minDNSTTL {
			fs.minDNSTTL = pkt.DNSMinRespTTL
		}
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

		ja3h := fs.ja3Hash
		isQUIC := fs.isQUIC
		nxdomainCount := fs.nxdomainCount
		minDNSTTL := fs.minDNSTTL
		rec := FlowRecord{
			SrcIP:         key.SrcIP,
			DstIP:         key.DstIP,
			SrcPort:       fs.srcPort,
			DstPort:       key.DstPort,
			Protocol:      key.Proto,
			PacketCount:   fs.packetCount,
			ByteCount:     fs.byteCount,
			FirstSeen:     fs.firstSeen,
			LastSeen:      fs.lastSeen,
			DNSQueries:    dnsSlice,
			TLSSNIName:    sniName,
			JA3Hash:       ja3h,
			IsQUIC:        isQUIC,
			NXDomainCount: nxdomainCount,
			MinDNSTTL:     minDNSTTL,
		}
		fs.mu.Unlock()

		if !rec.LastSeen.IsZero() && !rec.FirstSeen.IsZero() {
			rec.DurationMs = rec.LastSeen.Sub(rec.FirstSeen).Milliseconds()
		}
		if resolver != nil {
			if snap := resolver(rec.SrcIP, rec.SrcPort, rec.DstIP, rec.DstPort, rec.Protocol); snap != nil {
				rec.PID = snap.PID
				rec.ProcessName = snap.Name
				rec.BinaryPath = snap.BinaryPath
				rec.Cmdline = snap.Cmdline
				rec.ParentPID = snap.ParentPID
				rec.ParentName = snap.ParentName
				rec.Username = snap.Username
				rec.CreateTime = snap.CreateTime
			}
		}
		items = append(items, interim{rec: rec, key: key, timestamps: tsCopy})
		return true
	})

	// ── Pass 2: parallel reverse-DNS (semaphore-bounded) ─────────────────────
	sem := make(chan struct{}, config.Get().Capture.DNSWorkers)
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

	// ── Pass 2.5: GeoIP + JA3 known-bad enrichment (synchronous, cached) ─────
	extraJA3 := config.Get().Scoring.ExtraJA3BadHashes
	for i := range items {
		if gi := intel.Lookup(items[i].rec.DstIP); gi != nil {
			items[i].rec.Country = gi.CountryCode
			items[i].rec.ASNOrg = gi.OrgName
			items[i].rec.GeoHighRisk = gi.IsHighRisk
		}
		if items[i].rec.JA3Hash != "" {
			if family, ok := ja3.LookupWithFeed(items[i].rec.JA3Hash, extraJA3); ok {
				items[i].rec.JA3KnownBad = family
			}
		}
	}

	// ── Pass 3: per-flow scoring ──────────────────────────────────────────────
	records := make([]FlowRecord, len(items))
	for i, it := range items {
		it.rec.SuspicionScore, it.rec.SuspicionReasons = score(it.key, it.rec, it.timestamps)
		it.rec.MITRETechniques = intel.TagFlow(it.rec.SuspicionReasons)
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
	scanCfg := config.Get().Scoring
	for i := range records {
		n := len(dstsBySrc[records[i].SrcIP])
		var bonus float64
		var reason string
		switch {
		case n >= scanCfg.ScanConfirmedDests:
			bonus = 3.0
			reason = fmt.Sprintf("scan pattern: %d unique destinations from same source", n)
		case n >= scanCfg.ScanPossibleDests:
			bonus = 1.5
			reason = fmt.Sprintf("possible scan: %d unique destinations from same source", n)
		}
		if bonus > 0 {
			records[i].SuspicionScore = min(10.0, records[i].SuspicionScore+bonus)
			records[i].SuspicionReasons = append(records[i].SuspicionReasons, reason)
			records[i].MITRETechniques = intel.TagFlow(records[i].SuspicionReasons)
			records[i].RiskLevel = riskLabel(records[i].SuspicionScore)
		}
	}

	// ── Pass 5: asymmetric upload detection (cross-flow) ─────────────────────
	// Build a fast lookup from FlowKey → record index so we can find reverse flows
	// (server→client) to compare upload vs download byte counts.
	if !config.Get().Scoring.DisableAsymmetricScoring {
		byKey := make(map[FlowKey]int, len(records))
		for i, r := range records {
			byKey[FlowKey{SrcIP: r.SrcIP, DstIP: r.DstIP, DstPort: r.DstPort, Proto: r.Protocol}] = i
		}
		asymRatio := config.Get().Scoring.AsymmetricUploadRatio
		for i, r := range records {
			// The reverse flow key: server IP → client IP, DstPort = client's ephemeral SrcPort.
			revKey := FlowKey{SrcIP: r.DstIP, DstIP: r.SrcIP, DstPort: r.SrcPort, Proto: r.Protocol}
			j, ok := byKey[revKey]
			if !ok {
				continue
			}
			downBytes := records[j].ByteCount // bytes server→client
			upBytes := r.ByteCount            // bytes client→server
			if downBytes <= 0 || upBytes <= int64(float64(downBytes)*asymRatio) {
				continue
			}
			ratio := float64(upBytes) / float64(downBytes)
			reason := fmt.Sprintf("asymmetric upload ratio=%.1f (sent=%.0fKB recv=%.0fKB) — potential exfiltration",
				ratio, float64(upBytes)/1024, float64(downBytes)/1024)
			records[i].SuspicionScore = min(10.0, records[i].SuspicionScore+2.0)
			records[i].SuspicionReasons = append(records[i].SuspicionReasons, reason)
			records[i].MITRETechniques = intel.TagFlow(records[i].SuspicionReasons)
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

// isExemptedProcess reports whether the process name matches any exempted process
// in the config. Comparison is case-insensitive.
func isExemptedProcess(name string, exempted []string) bool {
	if name == "" || len(exempted) == 0 {
		return false
	}
	lower := strings.ToLower(name)
	for _, ex := range exempted {
		if strings.ToLower(ex) == lower {
			return true
		}
	}
	return false
}

// knownBrowsers are process name substrings that indicate a web browser.
// Browsers legitimately use QUIC (HTTP/3) so QUIC from a browser is not suspicious.
var knownBrowsers = map[string]bool{
	"chrome": true, "chromium": true, "firefox": true, "safari": true,
	"msedge": true, "edge": true, "opera": true, "brave": true,
	"vivaldi": true, "iexplore": true,
}

// isBrowserProcess returns true when the process name matches a known browser.
func isBrowserProcess(name string) bool {
	lower := strings.ToLower(name)
	for b := range knownBrowsers {
		if strings.Contains(lower, b) {
			return true
		}
	}
	return false
}

// lateralMovementSignal returns a (score, reason) for RFC1918→RFC1918 traffic on
// sensitive ports. Returns (0, "") when the port is not a lateral-movement indicator.
func lateralMovementSignal(dstPort uint16) (float64, string) {
	switch dstPort {
	case 445:
		return 2.5, "lateral movement: SMB on internal network (port 445)"
	case 3389:
		return 2.5, "lateral movement: RDP on internal network (port 3389)"
	case 5985:
		return 2.0, "lateral movement: WinRM HTTP on internal network (port 5985)"
	case 5986:
		return 2.0, "lateral movement: WinRM HTTPS on internal network (port 5986)"
	case 135:
		return 2.0, "lateral movement: WMI/DCOM RPC on internal network (port 135)"
	case 389:
		return 1.5, "lateral movement: LDAP on internal network (port 389)"
	case 636:
		return 1.5, "lateral movement: LDAPS on internal network (port 636)"
	case 22:
		return 1.0, "internal SSH: potential lateral movement (port 22)"
	}
	return 0, ""
}

func score(key FlowKey, rec FlowRecord, ts []time.Time) (float64, []string) {
	cfg := config.Get().Scoring
	var total float64
	var reasons []string

	add := func(pts float64, reason string) {
		total += pts
		reasons = append(reasons, reason)
	}

	// ── Port analysis ───────────────────────────────────────────────────────
	if !cfg.DisablePortScoring {
		effectiveBadPorts := knownBadPorts
		if len(cfg.ExtraBadPorts) > 0 {
			effectiveBadPorts = make(map[uint16]string, len(knownBadPorts)+len(cfg.ExtraBadPorts))
			for k, v := range knownBadPorts {
				effectiveBadPorts[k] = v
			}
			for _, p := range cfg.ExtraBadPorts {
				if effectiveBadPorts[uint16(p)] == "" {
					effectiveBadPorts[uint16(p)] = "user-defined bad port"
				}
			}
		}
		effectiveStdPorts := standardPorts
		if len(cfg.ExtraStandardPorts) > 0 {
			effectiveStdPorts = make(map[uint16]bool, len(standardPorts)+len(cfg.ExtraStandardPorts))
			for k, v := range standardPorts {
				effectiveStdPorts[k] = v
			}
			for _, p := range cfg.ExtraStandardPorts {
				effectiveStdPorts[uint16(p)] = true
			}
		}
		if why, bad := effectiveBadPorts[key.DstPort]; bad {
			add(4.0, fmt.Sprintf("known high-risk port %d (%s)", key.DstPort, why))
		} else if key.DstPort < 49152 && !effectiveStdPorts[key.DstPort] {
			add(1.0, fmt.Sprintf("non-standard port %d", key.DstPort))
		}
	}

	// ── Reverse DNS analysis ────────────────────────────────────────────────
	if !cfg.DisableReverseDNSScoring {
		if rec.ReverseDNS == "" && !isPrivateIP(rec.DstIP) {
			add(0.8, "no reverse DNS — direct IP connection")
		}
	}

	// ── DNS exfiltration ────────────────────────────────────────────────────
	if !cfg.DisableDNSExfilScoring {
		for _, q := range rec.DNSQueries {
			if isHighEntropyDomain(q) {
				add(2.5, fmt.Sprintf("possible DNS exfiltration: high-entropy query %q", q))
				break // one penalty per flow
			}
		}
	}

	// ── TLS SNI analysis ────────────────────────────────────────────────────
	if !cfg.DisableSNIScoring && key.Proto == "TCP" {
		// Missing SNI on an encrypted port is suspicious: legitimate TLS
		// clients always send SNI; C2 frameworks sometimes omit it.
		if rec.TLSSNIName == "" && (key.DstPort == 443 || key.DstPort == 8443) && rec.PacketCount > 3 {
			add(0.7, "TLS traffic on HTTPS port without SNI — potential evasion or non-standard TLS")
		}
		// Connection to a known DoH provider may indicate DNS tunneling or
		// covert use of DNS-over-HTTPS by a non-browser process.
		if rec.TLSSNIName != "" && dohProviders[strings.ToLower(rec.TLSSNIName)] {
			add(0.5, fmt.Sprintf("connection to DNS-over-HTTPS provider: %s", rec.TLSSNIName))
		}
	}

	// ── JA3 TLS fingerprint ─────────────────────────────────────────────────
	if !cfg.DisableJA3Scoring && rec.JA3KnownBad != "" {
		add(4.0, fmt.Sprintf("JA3 fingerprint matches known malware: %s [%s]", rec.JA3KnownBad, rec.JA3Hash))
	}

	// ── GeoIP / threat intelligence ─────────────────────────────────────────
	if !cfg.DisableGeoScoring && rec.GeoHighRisk {
		add(1.5, fmt.Sprintf("destination in high-risk ASN: %s", rec.ASNOrg))
	}

	// ── Process / binary analysis ───────────────────────────────────────────
	if !cfg.DisableBinaryPathScoring {
		if !isExemptedProcess(rec.ProcessName, cfg.ExemptedProcesses) {
			if rec.PID > 0 && rec.BinaryPath == "" {
				add(1.0, "could not resolve binary path for PID")
			}
			effectivePaths := suspiciousPathPrefixes
			if len(cfg.ExtraSuspiciousPaths) > 0 {
				effectivePaths = append(effectivePaths, cfg.ExtraSuspiciousPaths...)
			}
			for _, prefix := range effectivePaths {
				if strings.Contains(rec.BinaryPath, prefix) {
					add(2.5, fmt.Sprintf("binary running from suspicious path: %s", rec.BinaryPath))
					break
				}
			}
		}
	}

	// ── Cmdline analysis ────────────────────────────────────────────────────
	if !cfg.DisableCmdlineScoring && rec.Cmdline != "" {
		// Use pre-compiled patterns (compiled once at config load, not per-flow).
		effectivePatterns := suspiciousCmdlinePatterns
		if len(cfg.CompiledExtraCmdlinePatterns) > 0 {
			effectivePatterns = append(effectivePatterns, cfg.CompiledExtraCmdlinePatterns...)
		}
		for _, re := range effectivePatterns {
			if re.MatchString(rec.Cmdline) {
				add(2.0, fmt.Sprintf("suspicious cmdline pattern %q in: %s", re.String(), rec.Cmdline))
				break
			}
		}
	}

	// ── Beaconing detection ─────────────────────────────────────────────────
	if !cfg.DisableBeaconingScoring && !isExemptedProcess(rec.ProcessName, cfg.ExemptedProcesses) {
		if bs, reason := beaconingScore(ts, cfg); bs > 0 {
			add(bs, reason)
		}
	}

	// ── High data volume ────────────────────────────────────────────────────
	if rec.ByteCount > 5*1024*1024 {
		add(0.5, fmt.Sprintf("high data transfer: %.1f MB", float64(rec.ByteCount)/1024/1024))
	}

	// ── High transfer rate (potential rapid exfiltration) ───────────────────
	// Only score when duration is meaningful (> 1 s) and data volume is significant.
	if rec.DurationMs > 1000 && rec.ByteCount > 2*1024*1024 {
		bps := float64(rec.ByteCount) / (float64(rec.DurationMs) / 1000.0)
		if bps > 20*1024*1024 { // > 20 MB/s sustained outbound
			add(1.0, fmt.Sprintf("very high transfer rate: %.0f MB/s — potential rapid exfiltration", bps/1024/1024))
		}
	}

	// ── Long-lived connection ────────────────────────────────────────────────
	// A connection open for > 10 minutes with regular traffic is a strong C2
	// indicator when combined with other signals.
	const longLivedMs = 10 * 60 * 1000 // 10 min
	if rec.DurationMs > longLivedMs && len(ts) >= cfg.BeaconingMinPackets {
		minutes := float64(rec.DurationMs) / 60000.0
		add(0.5, fmt.Sprintf("long-lived connection: %.0f minutes with %d packets", minutes, len(ts)))
	}

	// ── QUIC (HTTP/3) from non-browser process ───────────────────────────────
	if !cfg.DisableQUICScoring && rec.IsQUIC {
		// Also honour the process exemption list so operators can silence
		// known-good QUIC users (e.g. "node", "quiche-test") without disabling
		// the entire QUIC signal.
		if rec.ProcessName != "" &&
			!isBrowserProcess(rec.ProcessName) &&
			!isExemptedProcess(rec.ProcessName, cfg.ExemptedProcesses) {
			add(1.5, fmt.Sprintf("QUIC connection from non-browser process: %s", rec.ProcessName))
		}
		if rec.GeoHighRisk {
			add(1.0, fmt.Sprintf("QUIC connection to high-risk ASN: %s", rec.ASNOrg))
		}
	}

	// ── Lateral movement (RFC1918 → RFC1918 on sensitive ports) ─────────────
	if !cfg.DisableLateralMovementScoring && isPrivateIP(rec.SrcIP) && isPrivateIP(rec.DstIP) {
		if pts, reason := lateralMovementSignal(key.DstPort); pts > 0 {
			add(pts, reason)
		}
	}

	// ── Protocol anomaly ─────────────────────────────────────────────────────
	if !cfg.DisableProtocolAnomalyScoring {
		// Non-TLS traffic on port 443: many TCP packets but no TLS ClientHello seen.
		if key.Proto == "TCP" && key.DstPort == 443 && rec.PacketCount > 10 &&
			rec.JA3Hash == "" && !rec.IsQUIC {
			add(1.5, "non-TLS traffic on TCP port 443 — potential protocol tunnel")
		}
		// Excessive DNS over TCP: large data volume on port 53 suggests tunneling.
		if key.DstPort == 53 && key.Proto == "TCP" && rec.ByteCount > 512*1024 {
			add(1.5, fmt.Sprintf("excessive DNS over TCP: %.0f KB — potential DNS exfiltration",
				float64(rec.ByteCount)/1024))
		}
	}

	// ── DNS response analysis (NXDOMAIN storm, fast-flux TTL) ───────────────
	if !cfg.DisableDNSExfilScoring {
		if rec.NXDomainCount >= cfg.NXDomainStormThreshold {
			add(2.0, fmt.Sprintf("dns nxdomain storm: %d NXDOMAIN responses — potential DGA activity",
				rec.NXDomainCount))
		}
		if rec.MinDNSTTL > 0 && rec.MinDNSTTL < uint32(cfg.FastFluxTTLThreshold) {
			add(1.5, fmt.Sprintf("low dns ttl=%d seconds — potential fast-flux or DGA domain",
				rec.MinDNSTTL))
		}
	}

	if total > 10.0 {
		total = 10.0
	}
	return total, reasons
}

// beaconingScore computes a score contribution based on inter-arrival
// time regularity. Low coefficient-of-variation → beaconing.
func beaconingScore(ts []time.Time, cfg config.ScoringConfig) (float64, string) {
	// Require at least cfg.BeaconingMinPackets for statistical validity.
	if len(ts) < cfg.BeaconingMinPackets {
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
	// Skip very short-interval flows (e.g. sub-100ms polling loops) that have
	// naturally low CV but are not C2 beacons. BeaconingMinIntervalSec == 0
	// (the default) disables this guard entirely.
	if cfg.BeaconingMinIntervalSec > 0 && mean < cfg.BeaconingMinIntervalSec*1000 {
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
	case cv < cfg.BeaconingStrongCV:
		return 3.5, fmt.Sprintf("strong beaconing pattern (interval CV=%.2f, mean=%.0f ms)", cv, mean)
	case cv < cfg.BeaconingPossibleCV:
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

// lookupReverseDNS returns the PTR hostname for ip, using a bounded LRU cache
// to avoid redundant DNS queries across repeated tool calls.
// Empty string is cached for negative results (no PTR record).
func lookupReverseDNS(ip string) string {
	if hostname, ok := dnsCache.Get(ip); ok {
		return hostname
	}
	hostname := doLookupReverseDNS(ip)
	dnsCache.Set(ip, hostname, getDNSCacheTTL())
	return hostname
}

// doLookupReverseDNS performs the actual PTR query with a configured deadline.
func doLookupReverseDNS(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.Get().Capture.DNSTimeoutMS)*time.Millisecond)
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
func isHighEntropyDomain(fqdn string) bool {
	fqdn = strings.TrimSuffix(fqdn, ".")
	parts := strings.Split(fqdn, ".")
	// Ignore the public-suffix (TLD + registrable label).
	if len(parts) <= 2 {
		return false
	}
	dnsCfg := config.Get().Scoring
	for _, label := range parts[:len(parts)-2] {
		if len(label) == 0 {
			continue
		}
		if len(label) > dnsCfg.DNSLabelLenThreshold {
			return true
		}
		if shannonEntropy(label) > dnsCfg.DNSEntropyThreshold {
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
