package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/alerting"
	"github.com/ClementG91/MCP-FlowSentinel/internal/baseline"
	"github.com/ClementG91/MCP-FlowSentinel/internal/capture"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
	"github.com/ClementG91/MCP-FlowSentinel/internal/correlate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/history"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// captureFunc matches capture.CapturePackets.
type captureFunc func(ctx context.Context, iface, bpfFilter string) (<-chan capture.PacketEvent, error)

// daemonEnv isolates every global the daemon touches: config, history,
// alert log, baseline cache and the capture/socket-table/clock seams.
type daemonEnv struct {
	cfg     *config.Config
	histDir string
	clock   time.Time
}

func newDaemonEnv(t *testing.T) *daemonEnv {
	t.Helper()
	dir := t.TempDir()

	origCfg := config.Get()
	cfg := config.Default()
	cfg.Daemon.Interfaces = []string{"test0"}
	cfg.Daemon.CaptureIntervalSec = 5
	cfg.Alerting.Enabled = false
	cfg.Metrics.Enabled = false
	config.Set(cfg)

	history.SetPathForTesting(filepath.Join(dir, "history.jsonl"))
	alerting.SetAlertLogPathForTesting(filepath.Join(dir, "alerts.jsonl"))
	// runWindow persists the baseline; keep it out of the real user cache.
	baseline.Init(filepath.Join(dir, "cache", "mcp-flowsentinel"))

	env := &daemonEnv{cfg: cfg, histDir: dir, clock: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)}

	origCapture, origList, origTable, origNow, origGetenv := capturePackets, listInterfaces, buildSocketTable, now, getenv
	buildSocketTable = func(*correlate.ProcCache) *correlate.SocketTable { return nil }
	now = func() time.Time { return env.clock }
	getenv = func(key string) string {
		if key == "XDG_CACHE_HOME" {
			return filepath.Join(dir, "cache")
		}
		return os.Getenv(key)
	}
	capturePackets = func(context.Context, string, string) (<-chan capture.PacketEvent, error) {
		t.Error("unexpected live capture")
		return nil, errors.New("live capture disabled in tests")
	}
	listInterfaces = func() ([]capture.Interface, error) {
		t.Error("unexpected interface enumeration")
		return nil, errors.New("interface enumeration disabled in tests")
	}

	t.Cleanup(func() {
		capturePackets, listInterfaces, buildSocketTable, now, getenv = origCapture, origList, origTable, origNow, origGetenv
		config.Set(origCfg)
		history.SetPathForTesting(filepath.Join(dir, "unused.jsonl"))
		baseline.Init(filepath.Join(dir, "unused-cache"))
		running.Store(false)
	})
	return env
}

// writeTestPcap writes Ethernet/IPv4/TCP packets from 10.0.0.2 to each
// destination port with the pure-Go pcap writer.
func writeTestPcap(t *testing.T, dstPorts ...uint16) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "window.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 9, 21, 11, 59, 0, 0, time.UTC)
	for i, port := range dstPorts {
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
			DstMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 6},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
			SrcIP: net.IPv4(10, 0, 0, 2).To4(), DstIP: net.IPv4(198, 51, 100, 7).To4(),
		}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(40000 + i), DstPort: layers.TCPPort(port), SYN: true, Seq: 1}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
			t.Fatal(err)
		}
		data := buf.Bytes()
		ci := gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(i) * time.Second), CaptureLength: len(data), Length: len(data)}
		if err := w.WritePacket(ci, data); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// offlineCapture replays path for every interface through the existing
// offline reader and records the interfaces it was asked to open.
func offlineCapture(path string, seen *sync.Map) captureFunc {
	return func(ctx context.Context, iface, bpfFilter string) (<-chan capture.PacketEvent, error) {
		seen.Store(iface, bpfFilter)
		return capture.OfflineReader{FilePath: path}.Read(ctx)
	}
}

func historyEntries(t *testing.T) []history.Entry {
	t.Helper()
	entries, err := history.Query(history.QueryOpts{MaxAge: 365 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("history.Query: %v", err)
	}
	return entries
}

func TestRunWindow_OfflineCaptureScoresAndPersistsFlows(t *testing.T) {
	env := newDaemonEnv(t)
	var seen sync.Map
	capturePackets = offlineCapture(writeTestPcap(t, 443, 8443), &seen)

	windowsBefore, flowsBefore := windowsRun.Load(), flowsScored.Load()
	if err := runWindow(context.Background(), []string{"test0"}, "tcp", time.Second, correlate.NewProcCache()); err != nil {
		t.Fatalf("runWindow: %v", err)
	}

	if got := windowsRun.Load() - windowsBefore; got != 1 {
		t.Errorf("windowsRun delta = %d, want 1", got)
	}
	if got := flowsScored.Load() - flowsBefore; got != 2 {
		t.Errorf("flowsScored delta = %d, want 2", got)
	}
	if filter, ok := seen.Load("test0"); !ok || filter != "tcp" {
		t.Errorf("capture called with filter %v (ok=%v), want tcp on test0", filter, ok)
	}
	entries := historyEntries(t)
	if len(entries) != 1 || entries[0].Source != "daemon:test0" || entries[0].FlowCount != 2 {
		t.Fatalf("history = %+v, want one daemon:test0 entry with 2 flows", entries)
	}
	if _, err := os.Stat(filepath.Join(env.histDir, "cache", "mcp-flowsentinel")); err != nil {
		t.Errorf("baseline was not persisted under XDG_CACHE_HOME: %v", err)
	}
}

func TestRunWindow_MultipleInterfacesShareOneWindow(t *testing.T) {
	newDaemonEnv(t)
	var seen sync.Map
	capturePackets = offlineCapture(writeTestPcap(t, 443), &seen)

	if err := runWindow(context.Background(), []string{"test0", "test1"}, "", time.Second, correlate.NewProcCache()); err != nil {
		t.Fatalf("runWindow: %v", err)
	}
	for _, name := range []string{"test0", "test1"} {
		if _, ok := seen.Load(name); !ok {
			t.Errorf("interface %s was not captured", name)
		}
	}
	entries := historyEntries(t)
	if len(entries) != 1 || entries[0].Source != "daemon:2-interfaces" {
		t.Fatalf("history = %+v, want one daemon:2-interfaces entry", entries)
	}
}

func TestRunWindow_CaptureErrorProducesEmptyWindow(t *testing.T) {
	newDaemonEnv(t)
	capturePackets = func(context.Context, string, string) (<-chan capture.PacketEvent, error) {
		return nil, errors.New("permission denied")
	}

	windowsBefore, flowsBefore := windowsRun.Load(), flowsScored.Load()
	if err := runWindow(context.Background(), []string{"test0"}, "", time.Second, correlate.NewProcCache()); err != nil {
		t.Fatalf("runWindow: %v", err)
	}
	if got := windowsRun.Load() - windowsBefore; got != 1 {
		t.Errorf("windowsRun delta = %d, want 1", got)
	}
	if got := flowsScored.Load() - flowsBefore; got != 0 {
		t.Errorf("flowsScored delta = %d, want 0", got)
	}
	if entries := historyEntries(t); len(entries) != 0 {
		t.Errorf("empty window wrote history: %+v", entries)
	}
}

func TestRun_CapturesConfiguredInterfacesUntilCancelled(t *testing.T) {
	env := newDaemonEnv(t)
	env.cfg.Daemon.Interfaces = []string{"test0", "test1"}
	env.cfg.Daemon.BPFFilter = "port 443"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pcap := writeTestPcap(t, 443)
	var calls atomic.Int32
	var during Stats
	var seen sync.Map
	replay := offlineCapture(pcap, &seen)
	capturePackets = func(c context.Context, iface, filter string) (<-chan capture.PacketEvent, error) {
		if calls.Add(1) == 1 {
			during = GetStats()
		}
		if iface == "test1" {
			cancel()
		}
		return replay(c, iface, filter)
	}

	if err := Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !during.Running || during.Interface != "test0" || strings.Join(during.Interfaces, ",") != "test0,test1" {
		t.Errorf("stats during run = %+v", during)
	}
	if !during.StartTime.Equal(env.clock) || during.IntervalSec != 5 {
		t.Errorf("stats start/interval = %v/%d, want %v/5", during.StartTime, during.IntervalSec, env.clock)
	}
	if filter, _ := seen.Load("test0"); filter != "port 443" {
		t.Errorf("BPF filter = %v, want port 443", filter)
	}
	if GetStats().Running {
		t.Error("daemon still reported running after Run returned")
	}
}

func TestRun_AutoSelectsInterface(t *testing.T) {
	env := newDaemonEnv(t)
	env.cfg.Daemon.Interfaces = nil
	env.cfg.Daemon.Interface = ""
	listInterfaces = func() ([]capture.Interface, error) {
		return []capture.Interface{
			{Name: "lo", Flags: []string{"loopback"}, Addresses: []string{"127.0.0.1/8"}},
			{Name: "eth9", Flags: []string{"up"}, Addresses: []string{"192.0.2.10/24"}},
		}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var got string
	capturePackets = func(context.Context, string, string) (<-chan capture.PacketEvent, error) {
		got = GetStats().Interface
		cancel()
		return nil, errors.New("stop")
	}

	if err := Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got != "eth9" {
		t.Errorf("auto-selected interface = %q, want eth9", got)
	}
}

func TestRun_AutoSelectFailures(t *testing.T) {
	tests := map[string]func() ([]capture.Interface, error){
		"enumeration error": func() ([]capture.Interface, error) { return nil, errors.New("no pcap") },
		"loopback only": func() ([]capture.Interface, error) {
			return []capture.Interface{{Name: "lo", Flags: []string{"loopback"}}}, nil
		},
	}
	for name, list := range tests {
		t.Run(name, func(t *testing.T) {
			env := newDaemonEnv(t)
			env.cfg.Daemon.Interfaces = nil
			listInterfaces = list
			err := Run(context.Background())
			if err == nil || !strings.Contains(err.Error(), "cannot auto-select interface") {
				t.Fatalf("Run() = %v, want auto-select error", err)
			}
			if GetStats().Running {
				t.Error("daemon marked running after failed start")
			}
		})
	}
}

func TestRun_StartsEnabledFeedUpdaters(t *testing.T) {
	env := newDaemonEnv(t)
	missing := filepath.Join(env.histDir, "missing-feed.txt")
	env.cfg.JA3Feed = config.JA3FeedConfig{Enabled: true, URLs: []string{"https://127.0.0.1:1/ja3.csv"}}
	env.cfg.HasshFeed = config.HasshFeedConfig{Enabled: true, LocalFile: missing}
	env.cfg.IPRep = config.IPRepConfig{Enabled: true, LocalFile: missing}
	env.cfg.DomRep = config.DomRepConfig{Enabled: true, LocalFile: missing}

	ctx, cancel := context.WithCancel(context.Background())
	capturePackets = func(context.Context, string, string) (<-chan capture.PacketEvent, error) {
		cancel()
		return nil, errors.New("stop")
	}
	if err := Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestFeedUpdaters_ReturnWhenContextCancelled(t *testing.T) {
	newDaemonEnv(t)
	missing := filepath.Join(t.TempDir(), "missing.txt")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	updaters := map[string]func(){
		"ja3":   func() { runJA3FeedUpdater(ctx, config.JA3FeedConfig{LocalFile: missing}) },
		"hassh": func() { runHasshFeedUpdater(ctx, config.HasshFeedConfig{LocalFile: missing, UpdateIntervalHours: 1}) },
		"iprep": func() { runIPRepUpdater(ctx, config.IPRepConfig{LocalFile: missing}) },
		"domrep": func() {
			runDomRepUpdater(ctx, config.DomRepConfig{LocalFile: missing, UpdateIntervalHours: 1})
		},
	}
	for name, run := range updaters {
		t.Run(name, func(t *testing.T) {
			done := make(chan struct{})
			go func() { run(); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("updater did not stop after context cancellation")
			}
		})
	}
}

func TestGetStats_ReportsUptimeFromClock(t *testing.T) {
	env := newDaemonEnv(t)
	startTimeMu.Lock()
	startTime = env.clock
	startTimeMu.Unlock()
	t.Cleanup(func() {
		startTimeMu.Lock()
		startTime = time.Time{}
		startTimeMu.Unlock()
	})
	env.clock = env.clock.Add(90 * time.Second)

	if got := GetStats().UptimeSec; got != 90 {
		t.Errorf("UptimeSec = %d, want 90", got)
	}
}

func TestBaselineCacheDir(t *testing.T) {
	orig := getenv
	t.Cleanup(func() { getenv = orig })

	getenv = func(string) string { return filepath.Join("xdg", "cache") }
	if got, want := baselineCacheDir(), filepath.Join("xdg", "cache", "mcp-flowsentinel"); got != want {
		t.Errorf("baselineCacheDir() with XDG = %q, want %q", got, want)
	}

	getenv = func(string) string { return "" }
	got := baselineCacheDir()
	if filepath.Base(got) != "mcp-flowsentinel" {
		t.Errorf("baselineCacheDir() without XDG = %q, want a mcp-flowsentinel directory", got)
	}
}
