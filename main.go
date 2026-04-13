// MCP-FlowSentinel — correlates live network traffic with local processes.
// Transport: stdio (compatible with Claude Desktop and any MCP client).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/alerting"
	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/capture"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
	"github.com/ClementG91/MCP-FlowSentinel/internal/daemon"
	"github.com/ClementG91/MCP-FlowSentinel/internal/intel"
	"github.com/ClementG91/MCP-FlowSentinel/internal/tools"
	"github.com/ClementG91/MCP-FlowSentinel/internal/updater"
	"github.com/mark3labs/mcp-go/server"
)

// version is injected at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	// Use stderr exclusively; stdout is reserved for the MCP JSON-RPC stream.
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Parse --config before the switch so all flags can use the loaded config.
	configPath := ""
	filteredArgs := os.Args[1:]
	for i := 0; i < len(filteredArgs); i++ {
		if filteredArgs[i] == "--config" && i+1 < len(filteredArgs) {
			configPath = filteredArgs[i+1]
			filteredArgs = append(filteredArgs[:i], filteredArgs[i+2:]...)
			break
		}
	}

	// Load config early so all subsystems share the same values.
	if _, err := config.Load(configPath); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	if len(filteredArgs) > 0 {
		switch filteredArgs[0] {
		case "--version", "-v":
			fmt.Printf("mcp-flowsentinel %s\n", version)
			return
		case "--check":
			runCheck()
			return
		case "--update":
			if err := updater.CheckAndUpdate(version); err != nil {
				fmt.Fprintf(os.Stderr, "update error: %v\n", err)
				os.Exit(1)
			}
			return
		case "--init-config":
			path := config.DefaultPath()
			if len(filteredArgs) > 1 {
				path = filteredArgs[1]
			}
			if err := config.WriteDefault(path); err != nil {
				fmt.Fprintf(os.Stderr, "init-config error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Config written to: %s\n", path)
			fmt.Println("Edit it then restart the server (or run with --config <path>).")
			return
		case "--validate-config":
			cfg := config.Get()
			data, _ := json.MarshalIndent(map[string]any{
				"status":      "ok",
				"loaded_from": config.LoadedPath(),
				"alerting_enabled": cfg.Alerting.Enabled,
				"min_score_threshold": cfg.Alerting.MinScoreThreshold,
			}, "", "  ")
			fmt.Println(string(data))
			fmt.Fprintln(os.Stderr, "Config valid.")
			return
		case "--test-alert":
			runTestAlert()
			return
		case "--daemon":
			runDaemon()
			return
		default:
			fmt.Fprintf(os.Stderr, "Usage: %s [options] [command]\n\n", os.Args[0])
			fmt.Fprintf(os.Stderr, "Commands:\n")
			fmt.Fprintf(os.Stderr, "  (none)            Start MCP server on stdio\n")
			fmt.Fprintf(os.Stderr, "  --daemon          Run continuous background monitoring + MCP server\n")
			fmt.Fprintf(os.Stderr, "  --check           Verify pcap access and list interfaces\n")
			fmt.Fprintf(os.Stderr, "  --init-config     Write a default config.yaml and exit\n")
			fmt.Fprintf(os.Stderr, "  --validate-config Validate loaded config and exit\n")
			fmt.Fprintf(os.Stderr, "  --test-alert      Send a test webhook alert and exit\n")
			fmt.Fprintf(os.Stderr, "  --update          Update to the latest release\n")
			fmt.Fprintf(os.Stderr, "  --version         Print version and exit\n\n")
			fmt.Fprintf(os.Stderr, "Options:\n")
			fmt.Fprintf(os.Stderr, "  --config <path>   Load config from path (default: %s)\n", config.DefaultPath())
			os.Exit(1)
		}
	}

	intel.Init() // load GeoIP databases (paths come from config or env vars)

	s := server.NewMCPServer("MCP-FlowSentinel", version)
	tools.Register(s)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Printf("MCP-FlowSentinel %s — stdio transport ready", version)

	if err := server.NewStdioServer(s).Listen(ctx, os.Stdin, os.Stdout); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

// runDaemon starts the continuous monitoring loop alongside the MCP server.
// The daemon captures rolling windows in the background while the MCP server
// remains available on stdio for on-demand queries.
func runDaemon() {
	intel.Init()

	s := server.NewMCPServer("MCP-FlowSentinel", version)
	tools.Register(s)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Run daemon capture loop in background goroutine.
	go func() {
		if err := daemon.Run(ctx); err != nil {
			log.Printf("daemon stopped: %v", err)
		}
	}()

	log.Printf("MCP-FlowSentinel %s — daemon mode + stdio transport ready", version)

	if err := server.NewStdioServer(s).Listen(ctx, os.Stdin, os.Stdout); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

// runCheck verifies pcap is accessible, prints available interfaces, and
// attempts a brief live capture to confirm end-to-end capture functionality.
// Privilege checks are delegated to the platform-specific checkPrivileges()
// function (privileges_unix.go on Linux/macOS, privileges_windows.go on Windows).
func runCheck() {
	fmt.Printf("MCP-FlowSentinel %s — system check\n\n", version)

	ok := true

	// ── Privilege check (platform-specific) ──────────────────────────────────
	if !checkPrivileges(os.Args[0]) {
		ok = false
	}

	// ── pcap interface enumeration ────────────────────────────────────────────
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		fmt.Printf("[FAIL] Could not list pcap interfaces: %v\n", err)
		fmt.Println()
		fmt.Println("       Ensure the pcap library is installed:")
		fmt.Println("         Linux  : sudo apt-get install libpcap-dev   (Debian/Ubuntu)")
		fmt.Println("                  sudo dnf install libpcap-devel      (Fedora/RHEL)")
		fmt.Println("         macOS  : brew install libpcap")
		fmt.Println("         Windows: install Npcap from https://npcap.com/#download")
		os.Exit(1)
	}

	fmt.Printf("[OK] pcap available — %d interface(s) found:\n", len(ifaces))
	for _, iface := range ifaces {
		addrs := iface.Addresses
		if len(addrs) == 0 {
			addrs = []string{"(no addresses)"}
		}
		label := iface.Name
		if iface.Description != "" {
			label = fmt.Sprintf("%s  (%s)", iface.Name, iface.Description)
		}
		fmt.Printf("       %-70s  flags=%-24v  addrs=%v\n", label, iface.Flags, addrs)
	}

	// ── Live capture smoke test (200 ms) ─────────────────────────────────────
	// Pick the first non-loopback interface by inspecting the flags slice;
	// this is cross-platform and avoids hard-coding "lo" / "loopback" names.
	testIface := ""
	for _, iface := range ifaces {
		isLoopback := false
		for _, f := range iface.Flags {
			if f == "loopback" {
				isLoopback = true
				break
			}
		}
		if !isLoopback {
			testIface = iface.Name
			break
		}
	}
	if testIface == "" && len(ifaces) > 0 {
		testIface = ifaces[0].Name // last resort: use whatever is available
	}

	if testIface != "" {
		label := testIface
		for _, iface := range ifaces {
			if iface.Name == testIface && iface.Description != "" {
				label = fmt.Sprintf("%s (%s)", testIface, iface.Description)
				break
			}
		}
		fmt.Printf("\n[..] Testing live capture on %q (200 ms)...\n", label)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		pktCh, capErr := capture.CapturePackets(ctx, testIface, "")
		if capErr != nil {
			fmt.Printf("[FAIL] Capture test failed: %v\n", capErr)
			fmt.Println("       Check privileges (see [WARN] above) and that pcap is installed.")
			ok = false
		} else {
			var count int
			for range pktCh {
				count++
			}
			fmt.Printf("[OK] Capture test succeeded — %d packet(s) observed in 200 ms.\n", count)
		}
	}

	fmt.Println()
	if ok {
		fmt.Println("All checks passed. Run without flags to start the MCP server on stdio.")
	} else {
		fmt.Println("Some checks failed — see [WARN]/[FAIL] above.")
		os.Exit(1)
	}
}

// runTestAlert fires a synthetic webhook alert to verify alerting configuration.
// It bypasses the dedup window so it always sends.
func runTestAlert() {
	cfg := config.Get()
	if !cfg.Alerting.Enabled {
		fmt.Fprintln(os.Stderr, "[WARN] Alerting is disabled in config (alerting.enabled = false).")
		fmt.Fprintln(os.Stderr, "       Set alerting.enabled: true and alerting.webhook_url to test.")
		os.Exit(1)
	}
	if cfg.Alerting.WebhookURL == "" {
		fmt.Fprintln(os.Stderr, "[FAIL] alerting.webhook_url is not set.")
		os.Exit(1)
	}

	testFlow := aggregate.FlowRecord{
		SrcIP:            "192.0.2.1",
		DstIP:            "203.0.113.42",
		SrcPort:          uint16(54321),
		DstPort:          uint16(443),
		Protocol:         "TCP",
		ProcessName:      "test-alert",
		SuspicionScore:   cfg.Alerting.MinScoreThreshold + 1,
		RiskLevel:        "TEST",
		SuspicionReasons: []string{"test alert — verify webhook connectivity"},
	}

	if err := alerting.FireTest(testFlow); err != nil {
		fmt.Fprintf(os.Stderr, "[FAIL] Test alert failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[OK] Test alert sent successfully.")
}
