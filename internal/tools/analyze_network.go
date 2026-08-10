package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/capture"
	"github.com/ClementG91/MCP-FlowSentinel/internal/config"
	"github.com/ClementG91/MCP-FlowSentinel/internal/correlate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/history"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ifaceNameRE allows Unix-style (eth0, en0, lo) and Windows NPF GUIDs
// (\Device\NPF_{...}) while rejecting shell metacharacters and path traversal.
var ifaceNameRE = regexp.MustCompile(`^[A-Za-z0-9_.:\\\-{}]+$`)

func registerAnalyzeNetwork(s *mcp.Server) {
	tool := newTool("analyze_network",
		withDescription(
			"Capture live network traffic on a named interface for a given duration, "+
				"correlate each flow with the local process that owns it, compute a "+
				"suspicion score (0–10), and return a JSON report sorted highest-risk first. "+
				"Requires root/admin privileges. Use list_interfaces to find valid interface names.",
		),
		withBehavior("Analyze live network traffic", false, false, true),
		withString("interface",
			required(),
			minLength(1),
			maxLength(256),
			description("Network interface name (e.g. eth0, en0, lo)."),
		),
		withNumber("duration_ms",
			minimum(1),
			maximum(60000),
			defaultValue(5000),
			description("Capture duration in milliseconds. Default: 5000 (5 s). Max: 60000."),
		),
		withString("bpf_filter",
			maxLength(4096),
			description(
				"Optional BPF filter expression (e.g. 'tcp port 443', 'host 1.2.3.4'). "+
					"Empty means capture all traffic.",
			),
		),
		withNumber("min_score",
			minimum(0),
			maximum(10),
			defaultValue(0),
			description(
				"Only return flows with suspicion_score >= this value (0–10). "+
					"Default: 0 (all flows). Use 2 to hide LOW noise, 5 to show HIGH+ only.",
			),
		),
		withInteger("top_n",
			minimum(0),
			maximum(10000),
			defaultValue(0),
			description(
				"Return at most this many flows (highest score first). "+
					"Default: 0 (unlimited). Use 20 to cap output size for busy interfaces.",
			),
		),
	)
	addTool(s, tool, analyzeNetworkHandler)
}

func analyzeNetworkHandler(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	// ── Parse arguments ──────────────────────────────────────────────────────
	ifaceName, _ := args["interface"].(string)
	if ifaceName == "" {
		return errorResult("'interface' parameter is required"), nil
	}
	if len(ifaceName) > 256 || !ifaceNameRE.MatchString(ifaceName) {
		return errorResult("invalid interface name — use list_interfaces to find valid names"), nil
	}

	capCfg := config.Get().Capture
	durationMS := float64(capCfg.DefaultDurationSec * 1000)
	if v, ok := args["duration_ms"].(float64); ok && v > 0 {
		durationMS = v
	}
	maxMS := float64(capCfg.MaxDurationSec * 1000)
	if durationMS > maxMS {
		durationMS = maxMS
	}

	bpfFilter, _ := args["bpf_filter"].(string)

	var minScore float64
	if v, ok := args["min_score"].(float64); ok && v > 0 {
		minScore = v
	}
	var topN int
	if v, ok := args["top_n"].(float64); ok && v > 0 {
		topN = int(v)
	}

	// ── Socket table with periodic refresh ──────────────────────────────────
	var tablePtr atomic.Pointer[correlate.SocketTable]
	tablePtr.Store(correlate.BuildSocketTable())

	resolver := makeResolver(&tablePtr)

	// ── Capture ──────────────────────────────────────────────────────────────
	capCtx, capCancel := context.WithTimeout(ctx, time.Duration(durationMS)*time.Millisecond)
	defer capCancel()

	// Refresh the socket table every 2 s for long captures.
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
		agg.Add(aggregate.FromCapturePacket(pkt, ifaceName))
		totalPackets++
	}

	// ── Score, filter, summarise ─────────────────────────────────────────────
	allFlows := agg.Finalize(resolver, nil)
	if err := history.Append("live:"+ifaceName, allFlows); err != nil {
		log.Printf("analyze_network: persist history: %v", err)
	}
	summary := aggregate.Summarise(allFlows) // summary over ALL flows before filtering
	flows := aggregate.FilterOptions{MinScore: minScore, TopN: topN}.Apply(allFlows)

	type captureInfo struct {
		Interface     string    `json:"interface"`
		DurationMs    float64   `json:"duration_ms"`
		BPFFilter     string    `json:"bpf_filter,omitempty"`
		TotalFlows    int       `json:"total_flows"`
		ReturnedFlows int       `json:"returned_flows"`
		TotalPackets  int64     `json:"total_packets"`
		MinScore      float64   `json:"min_score_filter,omitempty"`
		TopN          int       `json:"top_n_filter,omitempty"`
		Timestamp     time.Time `json:"timestamp"`
	}
	type response struct {
		CaptureInfo captureInfo            `json:"capture_info"`
		RiskSummary aggregate.RiskSummary  `json:"risk_summary"`
		Flows       []aggregate.FlowRecord `json:"flows"`
	}

	out, err := json.Marshal(response{
		CaptureInfo: captureInfo{
			Interface:     ifaceName,
			DurationMs:    durationMS,
			BPFFilter:     bpfFilter,
			TotalFlows:    len(allFlows),
			ReturnedFlows: len(flows),
			TotalPackets:  totalPackets,
			MinScore:      minScore,
			TopN:          topN,
			Timestamp:     time.Now().UTC(),
		},
		RiskSummary: summary,
		Flows:       flows,
	})
	if err != nil {
		return errorResult("failed to encode response: " + err.Error()), nil
	}
	return textResult(string(out)), nil
}

// makeResolver builds the ProcessResolver closure from an atomic SocketTable pointer.
// Extracted here so analyze_pcap can share the exact same mapping logic.
func makeResolver(tablePtr *atomic.Pointer[correlate.SocketTable]) aggregate.ProcessResolver {
	return func(srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string) *aggregate.ProcessSnapshot {
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
}
