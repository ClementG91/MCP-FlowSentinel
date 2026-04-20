// Package daemon provides continuous background network monitoring.
// It runs rolling capture windows and feeds flows into the history store
// so the MCP tools can answer questions about past and ongoing activity.
package daemon

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/alerting"
	"github.com/ClementG91/MCP-FlowSentinel/internal/baseline"
	"github.com/ClementG91/MCP-FlowSentinel/internal/capture"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
	"github.com/ClementG91/MCP-FlowSentinel/internal/correlate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/history"
	"github.com/ClementG91/MCP-FlowSentinel/internal/intel"
	"github.com/ClementG91/MCP-FlowSentinel/internal/ja3"
	"github.com/ClementG91/MCP-FlowSentinel/internal/metrics"
)

// ─── Runtime statistics ───────────────────────────────────────────────────────

var (
	running      atomic.Bool
	windowsRun   atomic.Int64
	flowsScored  atomic.Int64
	windowErrors atomic.Int64

	startTimeMu   sync.RWMutex
	startTime     time.Time
	activeIface   string
	activeIfacesMu sync.RWMutex
	activeIfaces  []string
)

// Stats holds a snapshot of the daemon's runtime metrics.
type Stats struct {
	Running         bool      `json:"running"`
	StartTime       time.Time `json:"start_time,omitempty"`
	UptimeSec       int64     `json:"uptime_seconds,omitempty"`
	Interface       string    `json:"interface,omitempty"`
	Interfaces      []string  `json:"interfaces,omitempty"`
	IntervalSec     int       `json:"interval_seconds"`
	WindowsRun      int64     `json:"windows_run"`
	FlowsScored     int64     `json:"flows_scored"`
	AlertsFired     int64     `json:"alerts_fired"`
	WebhookFailures int64     `json:"webhook_failures"`
	WindowErrors    int64     `json:"window_errors"`
	DroppedPackets  uint64    `json:"dropped_packets"`
	JA3FeedSize     int       `json:"ja3_feed_size,omitempty"`
}

// GetStats returns a snapshot of the daemon's current runtime metrics.
func GetStats() Stats {
	startTimeMu.RLock()
	st := startTime
	iface := activeIface
	startTimeMu.RUnlock()

	activeIfacesMu.RLock()
	ifaces := make([]string, len(activeIfaces))
	copy(ifaces, activeIfaces)
	activeIfacesMu.RUnlock()

	s := Stats{
		Running:         running.Load(),
		Interface:       iface,
		Interfaces:      ifaces,
		IntervalSec:     config.Get().Daemon.CaptureIntervalSec,
		WindowsRun:      windowsRun.Load(),
		FlowsScored:     flowsScored.Load(),
		AlertsFired:     alerting.FiredCount(),
		WebhookFailures: alerting.WebhookFailures(),
		WindowErrors:    windowErrors.Load(),
		DroppedPackets:  capture.DroppedPackets(),
		JA3FeedSize:     ja3.FeedSize(),
	}
	if !st.IsZero() {
		s.StartTime = st
		s.UptimeSec = int64(time.Since(st).Seconds())
	}
	return s
}

// ─── Daemon loop ──────────────────────────────────────────────────────────────

// Run starts the daemon capture loop. It blocks until ctx is cancelled.
// Each window is CaptureIntervalSec seconds; flows are appended to history
// and optionally sent to the configured webhook.
func Run(ctx context.Context) error {
	cfg := config.Get()
	dcfg := cfg.Daemon

	// Resolve interface list — support both legacy single-interface and new list.
	ifaces := resolveInterfaces(dcfg.Interface, dcfg.Interfaces)
	if len(ifaces) == 0 {
		auto, err := pickInterface()
		if err != nil {
			return fmt.Errorf("daemon: cannot auto-select interface: %w", err)
		}
		ifaces = []string{auto}
		log.Printf("daemon: auto-selected interface %q", auto)
	}

	primaryIface := ifaces[0]
	interval := time.Duration(dcfg.CaptureIntervalSec) * time.Second
	log.Printf("daemon: monitoring %v every %s", ifaces, interval)

	running.Store(true)
	startTimeMu.Lock()
	startTime = time.Now()
	activeIface = primaryIface
	startTimeMu.Unlock()
	activeIfacesMu.Lock()
	activeIfaces = ifaces
	activeIfacesMu.Unlock()
	defer running.Store(false)

	// Start Prometheus metrics server if enabled.
	if cfg.Metrics.Enabled {
		addr := cfg.Metrics.ListenAddr
		if addr == "" {
			addr = ":9200"
		}
		metrics.Serve(addr)
	}

	// Start JA3 feed updater if enabled.
	if cfg.JA3Feed.Enabled && len(cfg.JA3Feed.URLs) > 0 {
		go runJA3FeedUpdater(ctx, cfg.JA3Feed)
	}

	// Start HASSH feed updater if enabled.
	if cfg.HasshFeed.Enabled && (len(cfg.HasshFeed.URLs) > 0 || cfg.HasshFeed.LocalFile != "") {
		go runHasshFeedUpdater(ctx, cfg.HasshFeed)
	}

	// Start IP reputation feed updater if enabled.
	if cfg.IPRep.Enabled && (len(cfg.IPRep.URLs) > 0 || cfg.IPRep.LocalFile != "") {
		go runIPRepUpdater(ctx, cfg.IPRep)
	}

	// Initialise behavioural baseline from persisted state.
	// The cache directory mirrors the XDG_CACHE_HOME convention.
	baseline.Init(baselineCacheDir())

	// Shared process-metadata cache across all capture windows. Reusing it
	// means only new PIDs are resolved via gopsutil; existing ones are served
	// from memory, cutting repeated syscall overhead by 80-90%.
	procCache := correlate.NewProcCache()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		winStart := time.Now()
		if err := runWindow(ctx, ifaces, dcfg.BPFFilter, interval, procCache); err != nil {
			windowErrors.Add(1)
			log.Printf("daemon: window error: %v", err)
		}
		metrics.RecordWindowDuration(time.Since(winStart).Milliseconds())
		metrics.RecordDroppedPackets(capture.DroppedPackets())
	}
}

// runHasshFeedUpdater performs an initial HASSH feed fetch then refreshes on a ticker.
func runHasshFeedUpdater(ctx context.Context, hcfg config.HasshFeedConfig) {
	if err := capture.UpdateHasshFeed(hcfg.URLs, hcfg.LocalFile); err != nil {
		log.Printf("hasshfeed: initial update failed: %v", err)
	}
	interval := time.Duration(hcfg.UpdateIntervalHours) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := capture.UpdateHasshFeed(hcfg.URLs, hcfg.LocalFile); err != nil {
				log.Printf("hasshfeed: periodic update failed: %v", err)
			}
		}
	}
}

// runIPRepUpdater performs an initial IP reputation feed fetch then refreshes on a ticker.
func runIPRepUpdater(ctx context.Context, ircfg config.IPRepConfig) {
	if err := intel.UpdateIPRep(ircfg.URLs, ircfg.LocalFile); err != nil {
		log.Printf("iprep: initial update failed: %v", err)
	}
	interval := time.Duration(ircfg.UpdateIntervalHours) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := intel.UpdateIPRep(ircfg.URLs, ircfg.LocalFile); err != nil {
				log.Printf("iprep: periodic update failed: %v", err)
			}
		}
	}
}

// runJA3FeedUpdater performs an initial feed fetch then refreshes on a ticker.
func runJA3FeedUpdater(ctx context.Context, jcfg config.JA3FeedConfig) {
	// Immediate first fetch so the feed is populated before the first window.
	if err := ja3.UpdateFeed(jcfg.URLs, jcfg.LocalFile); err != nil {
		log.Printf("ja3feed: initial update failed: %v", err)
	}
	interval := time.Duration(jcfg.UpdateIntervalHours) * time.Hour
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ja3.UpdateFeed(jcfg.URLs, jcfg.LocalFile); err != nil {
				log.Printf("ja3feed: periodic update failed: %v", err)
			}
		}
	}
}

// runWindow captures one interval's worth of traffic across all interfaces,
// scores it, stores it in history, and fires alerting for high-score flows.
// Each interface runs in its own goroutine; the aggregator is safe for
// concurrent writes (sync.Map internally).
func runWindow(ctx context.Context, ifaces []string, bpfFilter string, dur time.Duration, procCache *correlate.ProcCache) error {
	winCtx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()

	var tablePtr atomic.Pointer[correlate.SocketTable]
	tablePtr.Store(correlate.BuildSocketTableCached(procCache))

	// Refresh socket table every 2 s for long windows.
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-winCtx.Done():
				return
			case <-ticker.C:
				tablePtr.Store(correlate.BuildSocketTableCached(procCache))
			}
		}
	}()

	agg := &aggregate.Aggregator{}

	// One capture goroutine per interface — all feed the same aggregator.
	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		go func(ifaceName string) {
			defer wg.Done()
			pktCh, err := capture.CapturePackets(winCtx, ifaceName, bpfFilter)
			if err != nil {
				log.Printf("daemon: capture %q: %v", ifaceName, err)
				return
			}
			for pkt := range pktCh {
				agg.Add(aggregate.PacketEvent{
					SrcIP:         pkt.SrcIP,
					DstIP:         pkt.DstIP,
					SrcPort:       pkt.SrcPort,
					DstPort:       pkt.DstPort,
					Proto:         pkt.Proto,
					PayloadLen:    pkt.PayloadLen,
					Timestamp:     pkt.Timestamp,
					DNSQuery:      pkt.DNSQuery,
					TLSSNIName:    pkt.TLSSNIName,
					JA3Hash:       pkt.JA3Hash,
					IsQUIC:        pkt.IsQUIC,
					IsHTTP2:        pkt.IsHTTP2,
					IsGRPC:         pkt.IsGRPC,
					IsIPv6RH0:      pkt.IsIPv6RH0,
					IsIPv6Fragment: pkt.IsIPv6Fragment,
					DNSNXDomain:   pkt.DNSNXDomain,
					DNSMinRespTTL: pkt.DNSMinRespTTL,
					HTTPMethod:    pkt.HTTPMethod,
					HTTPHost:      pkt.HTTPHost,
					HTTPUserAgent: pkt.HTTPUserAgent,
					HTTPURI:       pkt.HTTPURI,
					TLSCertInfo:   pkt.TLSCertInfo,
					JA3SHash:      pkt.JA3SHash,
					HasshHash:     pkt.HasshHash,
				})
			}
		}(iface)
	}
	wg.Wait()

	resolver := func(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) *aggregate.ProcessSnapshot {
		tbl := tablePtr.Load()
		if tbl == nil {
			return nil
		}
		info := tbl.Lookup(srcIP, srcPort, dstIP, dstPort, proto)
		if info == nil {
			return nil
		}
		return &aggregate.ProcessSnapshot{
			PID:        info.PID,
			Name:       info.Name,
			BinaryPath: info.BinaryPath,
			Cmdline:    info.Cmdline,
			ParentPID:  info.ParentPID,
			ParentName: info.ParentName,
			Username:   info.Username,
			CreateTime: info.CreateTime,
		}
	}

	flows := agg.Finalize(resolver)
	if len(flows) == 0 {
		windowsRun.Add(1)
		return nil
	}

	flowsScored.Add(int64(len(flows)))
	windowsRun.Add(1)

	// Feed the baseline with per-flow observations so future windows can
	// detect anomalies relative to historical behaviour.
	for _, f := range flows {
		baseline.Observe(f.ProcessName, f.DstPort, f.ByteCount)
	}
	// Flush baseline to disk after each window (atomic rename — cheap).
	if err := baseline.Persist(); err != nil {
		log.Printf("daemon: baseline persist: %v", err)
	}

	source := "daemon:" + ifaces[0]
	if len(ifaces) > 1 {
		source = fmt.Sprintf("daemon:%d-interfaces", len(ifaces))
	}
	history.Append(source, flows)
	alerting.Fire(flows)

	summary := aggregate.Summarise(flows)
	metrics.RecordFlows(summary.Critical, summary.High, summary.Medium, summary.Low, 0)
	log.Printf("daemon: window done — %d flows  critical=%d high=%d medium=%d low=%d ifaces=%v",
		len(flows), summary.Critical, summary.High, summary.Medium, summary.Low, ifaces)

	return nil
}

// baselineCacheDir returns the directory used to persist baseline statistics.
// Follows XDG_CACHE_HOME when set, otherwise ~/.cache/mcp-flowsentinel/.
func baselineCacheDir() string {
	if xdg := getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "mcp-flowsentinel")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "mcp-flowsentinel")
	}
	return filepath.Join(home, ".cache", "mcp-flowsentinel")
}

// getenv is a thin wrapper around os.Getenv used for testability.
var getenv = os.Getenv

// resolveInterfaces returns the effective interface list from config.
// Interfaces (new field) takes priority; Interface (legacy) is used when
// Interfaces is empty; empty result means auto-selection is needed.
func resolveInterfaces(single string, list []string) []string {
	if len(list) > 0 {
		return list
	}
	if single != "" {
		return []string{single}
	}
	return nil
}

// pickInterface returns the first non-loopback interface with an assigned
// unicast address, as a best-effort auto-selection for daemon mode.
func pickInterface() (string, error) {
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		return "", err
	}
	name := selectInterface(ifaces)
	if name == "" {
		return "", fmt.Errorf("no usable network interface found")
	}
	return name, nil
}

// selectInterface chooses the best interface from the given list.
// It prefers non-loopback interfaces that have at least one address;
// falls back to any non-loopback interface if none have addresses.
// Extracted for testability — no pcap dependency.
func selectInterface(ifaces []capture.Interface) string {
	for _, iface := range ifaces {
		if hasFlag(iface.Flags, "loopback") {
			continue
		}
		if len(iface.Addresses) > 0 {
			return iface.Name
		}
	}
	for _, iface := range ifaces {
		if !hasFlag(iface.Flags, "loopback") {
			return iface.Name
		}
	}
	return ""
}

// hasFlag returns true when target is present in the flags slice.
func hasFlag(flags []string, target string) bool {
	for _, f := range flags {
		if f == target {
			return true
		}
	}
	return false
}
