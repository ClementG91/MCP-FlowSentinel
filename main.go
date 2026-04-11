// MCP-FlowSentinel — correlates live network traffic with local processes.
// Transport: stdio (compatible with Claude Desktop and any MCP client).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/capture"
	"github.com/ClementG91/MCP-FlowSentinel/internal/updater"
	"github.com/mark3labs/mcp-go/server"

	"github.com/ClementG91/MCP-FlowSentinel/internal/tools"
)

// version is injected at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	// Use stderr exclusively; stdout is reserved for the MCP JSON-RPC stream.
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if len(os.Args) > 1 {
		switch os.Args[1] {
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
		default:
			fmt.Fprintf(os.Stderr, "Usage: %s [--version | --check | --update]\n", os.Args[0])
			fmt.Fprintf(os.Stderr, "  (no flags) — start MCP server on stdio\n")
			fmt.Fprintf(os.Stderr, "  --check    — verify pcap access and list interfaces\n")
			fmt.Fprintf(os.Stderr, "  --update   — update to the latest release\n")
			fmt.Fprintf(os.Stderr, "  --version  — print version and exit\n")
			os.Exit(1)
		}
	}

	s := server.NewMCPServer("MCP-FlowSentinel", version)
	tools.Register(s)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Printf("MCP-FlowSentinel %s — stdio transport ready", version)

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
