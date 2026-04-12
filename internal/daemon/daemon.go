// Package daemon provides continuous background network monitoring.
// It runs rolling capture windows and feeds flows into the history store
// so the MCP tools can answer questions about past and ongoing activity.
package daemon

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/alerting"
	"github.com/ClementG91/MCP-FlowSentinel/internal/capture"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
	"github.com/ClementG91/MCP-FlowSentinel/internal/correlate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/history"
)

// Run starts the daemon capture loop. It blocks until ctx is cancelled.
// Each window is CaptureIntervalSec seconds; flows are appended to history
// and optionally sent to the configured webhook.
func Run(ctx context.Context) error {
	dcfg := config.Get().Daemon

	iface := dcfg.Interface
	if iface == "" {
		auto, err := pickInterface()
		if err != nil {
			return fmt.Errorf("daemon: cannot auto-select interface: %w", err)
		}
		iface = auto
		log.Printf("daemon: auto-selected interface %q", iface)
	}

	interval := time.Duration(dcfg.CaptureIntervalSec) * time.Second
	log.Printf("daemon: monitoring %q every %s", iface, interval)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if err := runWindow(ctx, iface, dcfg.BPFFilter, interval); err != nil {
			log.Printf("daemon: window error: %v", err)
		}
	}
}

// runWindow captures one interval's worth of traffic, scores it, stores it
// in history, and fires alerting for high-score flows.
func runWindow(ctx context.Context, iface, bpfFilter string, dur time.Duration) error {
	winCtx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()

	var tablePtr atomic.Pointer[correlate.SocketTable]
	tablePtr.Store(correlate.BuildSocketTable())

	// Refresh socket table every 2 s for long windows.
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-winCtx.Done():
				return
			case <-ticker.C:
				tablePtr.Store(correlate.BuildSocketTable())
			}
		}
	}()

	pktCh, err := capture.CapturePackets(winCtx, iface, bpfFilter)
	if err != nil {
		return err
	}

	agg := &aggregate.Aggregator{}
	for pkt := range pktCh {
		agg.Add(aggregate.PacketEvent{
			SrcIP:      pkt.SrcIP,
			DstIP:      pkt.DstIP,
			SrcPort:    pkt.SrcPort,
			DstPort:    pkt.DstPort,
			Proto:      pkt.Proto,
			PayloadLen: pkt.PayloadLen,
			Timestamp:  pkt.Timestamp,
			DNSQuery:   pkt.DNSQuery,
			TLSSNIName: pkt.TLSSNIName,
			JA3Hash:    pkt.JA3Hash,
		})
	}

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
		return nil
	}

	history.Append("daemon:"+iface, flows)
	alerting.Fire(flows)

	// Log a brief summary.
	summary := aggregate.Summarise(flows)
	log.Printf("daemon: window done — %d flows  high=%d medium=%d low=%d",
		len(flows), summary.High, summary.Medium, summary.Low)

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

