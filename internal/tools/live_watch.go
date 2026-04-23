package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/capture"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
	"github.com/ClementG91/MCP-FlowSentinel/internal/correlate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/history"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerLiveWatch(s *server.MCPServer) {
	tool := mcp.NewTool("live_watch",
		mcp.WithDescription(
			"Watch a specific process and/or IP address in real time for up to 60 seconds. "+
				"Captures live traffic, scores each flow, and returns the result filtered to the "+
				"target. Useful for investigating 'is chrome.exe calling home?' or "+
				"'what is 1.2.3.4 doing?'. "+
				"Requires root/admin privileges and a valid interface name "+
				"(use list_interfaces to find one). "+
				"At least one of process_name or target_ip must be provided.",
		),
		mcp.WithString("interface",
			mcp.Required(),
			mcp.Description("Network interface to capture on (e.g. eth0, en0)."),
		),
		mcp.WithString("process_name",
			mcp.Description(
				"Case-insensitive substring match against process names. "+
					"Only flows whose owning process name contains this string are returned.",
			),
		),
		mcp.WithString("target_ip",
			mcp.Description(
				"Only return flows involving this IP address as source or destination.",
			),
		),
		mcp.WithNumber("duration_seconds",
			mcp.Description(
				"How long to capture (1–60 seconds). Default: 10.",
			),
		),
		mcp.WithNumber("min_score",
			mcp.Description(
				"Only return flows with suspicion_score >= this value (0–10). Default: 0.",
			),
		),
	)
	s.AddTool(tool, liveWatchHandler)
}

func liveWatchHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments

	ifaceName, _ := args["interface"].(string)
	if ifaceName == "" {
		return errorResult("'interface' parameter is required"), nil
	}
	if len(ifaceName) > 256 || !ifaceNameRE.MatchString(ifaceName) {
		return errorResult("invalid interface name — use list_interfaces to find valid names"), nil
	}

	processFilter, _ := args["process_name"].(string)
	targetIP, _ := args["target_ip"].(string)

	if processFilter == "" && targetIP == "" {
		return errorResult("provide at least one of 'process_name' or 'target_ip'"), nil
	}

	durationSec := 10.0
	if v, ok := args["duration_seconds"].(float64); ok && v > 0 {
		durationSec = v
	}
	maxSec := float64(config.Get().Capture.MaxDurationSec)
	if maxSec <= 0 {
		maxSec = 60
	}
	if durationSec > maxSec {
		durationSec = maxSec
	}

	var minScore float64
	if v, ok := args["min_score"].(float64); ok && v > 0 {
		minScore = v
	}

	// Build a BPF filter from targetIP to reduce pcap overhead.
	bpfFilter := ""
	if targetIP != "" {
		bpfFilter = "host " + targetIP
	}

	// Socket table with 2s refresh.
	var tablePtr atomic.Pointer[correlate.SocketTable]
	tablePtr.Store(correlate.BuildSocketTable())
	resolver := makeResolver(&tablePtr)

	capCtx, capCancel := context.WithTimeout(ctx, time.Duration(durationSec*1000)*time.Millisecond)
	defer capCancel()

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-capCtx.Done():
				return
			case <-ticker.C:
				tablePtr.Store(correlate.BuildSocketTable())
			}
		}
	}()

	pktCh, err := capture.CapturePackets(capCtx, ifaceName, bpfFilter)
	if err != nil {
		return errorResult(fmt.Sprintf("capture error: %v", err)), nil
	}

	agg := &aggregate.Aggregator{}
	var totalPackets int64
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
			IsHTTP2:       pkt.IsHTTP2,
			IsGRPC:        pkt.IsGRPC,
			DNSNXDomain:   pkt.DNSNXDomain,
			DNSMinRespTTL: pkt.DNSMinRespTTL,
			HTTPMethod:    pkt.HTTPMethod,
			HTTPHost:      pkt.HTTPHost,
			HTTPUserAgent: pkt.HTTPUserAgent,
			HTTPURI:       pkt.HTTPURI,
			TLSCertInfo:   pkt.TLSCertInfo,
			IsIPv6RH0:     pkt.IsIPv6RH0,
			IsIPv6Fragment: pkt.IsIPv6Fragment,
		})
		totalPackets++
	}

	allFlows := agg.Finalize(resolver, nil)

	// Filter to the requested process and/or IP.
	processFilterLow := strings.ToLower(processFilter)
	var filtered []aggregate.FlowRecord
	for _, f := range allFlows {
		if processFilterLow != "" {
			if !strings.Contains(strings.ToLower(f.ProcessName), processFilterLow) {
				continue
			}
		}
		if targetIP != "" {
			if f.SrcIP != targetIP && f.DstIP != targetIP {
				continue
			}
		}
		if f.SuspicionScore < minScore {
			continue
		}
		filtered = append(filtered, f)
	}

	// Sort highest-score first.
	for i := 0; i < len(filtered)-1; i++ {
		for j := i + 1; j < len(filtered); j++ {
			if filtered[j].SuspicionScore > filtered[i].SuspicionScore {
				filtered[i], filtered[j] = filtered[j], filtered[i]
			}
		}
	}

	// Persist to history so get_flow_history can find these flows later.
	if len(allFlows) > 0 {
		history.Append("watch:"+ifaceName, allFlows)
	}

	type watchInfo struct {
		Interface     string    `json:"interface"`
		DurationSec   float64   `json:"duration_seconds"`
		ProcessFilter string    `json:"process_filter,omitempty"`
		TargetIP      string    `json:"target_ip,omitempty"`
		BPFFilter     string    `json:"bpf_filter,omitempty"`
		TotalPackets  int64     `json:"total_packets"`
		TotalFlows    int       `json:"total_flows"`
		FilteredFlows int       `json:"filtered_flows"`
		Timestamp     time.Time `json:"timestamp"`
	}
	type response struct {
		WatchInfo watchInfo              `json:"watch_info"`
		RiskSummary aggregate.RiskSummary `json:"risk_summary"`
		Flows      []aggregate.FlowRecord `json:"flows"`
	}

	var flows []aggregate.FlowRecord
	if filtered != nil {
		flows = filtered
	} else {
		flows = []aggregate.FlowRecord{}
	}

	out, err := json.Marshal(response{
		WatchInfo: watchInfo{
			Interface:     ifaceName,
			DurationSec:   durationSec,
			ProcessFilter: processFilter,
			TargetIP:      targetIP,
			BPFFilter:     bpfFilter,
			TotalPackets:  totalPackets,
			TotalFlows:    len(allFlows),
			FilteredFlows: len(filtered),
			Timestamp:     time.Now().UTC(),
		},
		RiskSummary: aggregate.Summarise(filtered),
		Flows:       flows,
	})
	if err != nil {
		return errorResult("failed to encode response: " + err.Error()), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}
