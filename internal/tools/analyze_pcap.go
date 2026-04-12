package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/aggregate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/capture"
	"github.com/ClementG91/MCP-FlowSentinel/internal/correlate"
	"github.com/ClementG91/MCP-FlowSentinel/internal/history"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerAnalyzePcap(s *server.MCPServer) {
	tool := mcp.NewTool("analyze_pcap",
		mcp.WithDescription(
			"Analyze an existing .pcap or .pcapng file offline. Reads all packets from the "+
				"file, correlates flows with currently running processes (best-effort), applies "+
				"the same suspicion scoring as analyze_network, and returns a JSON report sorted "+
				"highest-risk first. Useful for forensic analysis of saved captures.",
		),
		mcp.WithString("file_path",
			mcp.Required(),
			mcp.Description("Absolute path to a .pcap or .pcapng capture file."),
		),
		mcp.WithString("bpf_filter",
			mcp.Description(
				"Optional BPF filter expression applied while reading "+
					"(e.g. 'tcp port 443', 'host 1.2.3.4'). Empty means read all packets.",
			),
		),
		mcp.WithNumber("min_score",
			mcp.Description(
				"Only return flows with suspicion_score >= this value (0–10). "+
					"Default: 0 (all flows). Use 2 to hide LOW noise, 5 to show HIGH+ only.",
			),
		),
		mcp.WithNumber("top_n",
			mcp.Description(
				"Return at most this many flows (highest score first). "+
					"Default: 0 (unlimited). Use 20 to cap output size.",
			),
		),
	)
	s.AddTool(tool, analyzePcapHandler)
}

func analyzePcapHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments

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
		totalPackets++
	}

	allFlows := agg.Finalize(resolver)
	history.Append("pcap:"+filePath, allFlows)
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
		CaptureInfo captureInfo           `json:"capture_info"`
		RiskSummary aggregate.RiskSummary `json:"risk_summary"`
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
	return mcp.NewToolResultText(string(out)), nil
}
