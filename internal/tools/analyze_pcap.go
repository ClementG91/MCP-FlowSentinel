package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/capture"
	"github.com/ClementG91/MCP-FlowSentinel/internal/correlate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/history"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerAnalyzePcap(s *mcp.Server) {
	tool := newTool("analyze_pcap",
		withDescription(
			"Analyze an existing .pcap or .pcapng file offline. Reads all packets from the "+
				"file, correlates flows with currently running processes (best-effort), applies "+
				"the same suspicion scoring as analyze_network, and returns a JSON report sorted "+
				"highest-risk first. Useful for forensic analysis of saved captures.",
		),
		withBehavior("Analyze a packet capture", false, false, false),
		withString("file_path",
			required(),
			minLength(1),
			maxLength(4096),
			description("Absolute path to a .pcap or .pcapng capture file."),
		),
		withString("bpf_filter",
			maxLength(4096),
			description(
				"Optional BPF filter expression applied while reading "+
					"(e.g. 'tcp port 443', 'host 1.2.3.4'). Empty means read all packets.",
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
					"Default: 0 (unlimited). Use 20 to cap output size.",
			),
		),
	)
	addTool(s, tool, analyzePcapHandler)
}

func analyzePcapHandler(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	filePath, _ := args["file_path"].(string)
	if filePath == "" {
		return errorResult("'file_path' parameter is required"), nil
	}

	// Sanitise and validate the path before any filesystem access.
	filePath = filepath.Clean(filePath)
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != ".pcap" && ext != ".pcapng" {
		return errorResult("file_path must have a .pcap or .pcapng extension"), nil
	}

	// Verify the file exists, is readable, and is not unreasonably large.
	fi, err := os.Stat(filePath)
	if err != nil {
		return errorResult(fmt.Sprintf("file not accessible: %v", err)), nil
	}
	const maxPcapSize = 1 << 30 // 1 GB
	if fi.Size() > maxPcapSize {
		return errorResult(fmt.Sprintf("pcap file too large (%.1f GB); maximum allowed is 1 GB", float64(fi.Size())/(1<<30))), nil
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

	// Single socket-table snapshot — the file is static so no refresh needed.
	var tablePtr atomic.Pointer[correlate.SocketTable]
	tablePtr.Store(correlate.BuildSocketTable())
	resolver := makeResolver(&tablePtr)

	// Read the pcap file. Use the caller's ctx so cancellation is respected.
	reader := capture.OfflineReader{FilePath: filePath, BPFFilter: bpfFilter}
	pktCh, err := reader.Read(ctx)
	if err != nil {
		return errorResult(fmt.Sprintf("could not open pcap file: %v", err)), nil
	}

	agg := &aggregate.Aggregator{}
	var totalPackets int64
	for pkt := range pktCh {
		agg.Add(aggregate.FromCapturePacket(pkt, ""))
		totalPackets++
	}

	allFlows := agg.Finalize(resolver, nil)
	if err := history.Append("pcap:"+filePath, allFlows); err != nil {
		log.Printf("analyze_pcap: persist history: %v", err)
	}
	summary := aggregate.Summarise(allFlows)
	flows := aggregate.FilterOptions{MinScore: minScore, TopN: topN}.Apply(allFlows)

	type captureInfo struct {
		Source        string    `json:"source"`
		FilePath      string    `json:"file_path"`
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
			Source:        "pcap_file",
			FilePath:      filePath,
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
