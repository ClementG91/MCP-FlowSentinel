package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/history"
	"github.com/ClementG91/MCP-FlowSentinel/internal/intel"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerAnalyzeProcess(s *server.MCPServer) {
	tool := mcp.NewTool("analyze_process",
		mcp.WithDescription(
			"Deep-dive analysis of a specific process's network activity. "+
				"Shows current open connections with GeoIP enrichment, full process metadata "+
				"(binary path, cmdline, parent chain), and a count of matching flows in the "+
				"24-hour history. "+
				"Provide either pid or process_name (or both).",
		),
		mcp.WithNumber("pid",
			mcp.Description("Exact PID to analyze. Takes precedence over process_name."),
		),
		mcp.WithString("process_name",
			mcp.Description(
				"Case-insensitive substring match against running process names. "+
					"Returns all matching processes when pid is not specified.",
			),
		),
	)
	s.AddTool(tool, analyzeProcessHandler)
}

// processReport is the per-process output structure.
type processReport struct {
	PID                int32              `json:"pid"`
	Name               string             `json:"name"`
	BinaryPath         string             `json:"binary_path,omitempty"`
	Cmdline            string             `json:"cmdline,omitempty"`
	Username           string             `json:"username,omitempty"`
	CreateTimeMs       int64              `json:"create_time_ms,omitempty"`
	ParentChain        []parentInfo       `json:"parent_chain,omitempty"`
	CurrentConnections []enrichedConn     `json:"current_connections"`
	HistoryFlowCount   int                `json:"history_flow_count_24h"`
	AnalyzedAt         time.Time          `json:"analyzed_at"`
}

type parentInfo struct {
	PID  int32  `json:"pid"`
	Name string `json:"name"`
}

type enrichedConn struct {
	Local       string `json:"local"`
	Remote      string `json:"remote"`
	State       string `json:"state"`
	Protocol    string `json:"protocol"`
	Country     string `json:"country,omitempty"`
	ASNOrg      string `json:"asn_org,omitempty"`
	GeoHighRisk bool   `json:"geo_high_risk,omitempty"`
}

func analyzeProcessHandler(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.Params.Arguments

	var targetPID int32
	if v, ok := args["pid"].(float64); ok && v > 0 {
		targetPID = int32(v)
	}
	nameFilter, _ := args["process_name"].(string)

	if targetPID == 0 && nameFilter == "" {
		return errorResult("provide 'pid' or 'process_name'"), nil
	}

	// Collect all running processes matching the criteria.
	procs, err := process.Processes()
	if err != nil {
		return errorResult(fmt.Sprintf("cannot list processes: %v", err)), nil
	}

	var matched []*process.Process
	for _, p := range procs {
		if targetPID > 0 && p.Pid == targetPID {
			matched = []*process.Process{p}
			break
		}
		if nameFilter != "" {
			name, _ := p.Name()
			if strings.Contains(strings.ToLower(name), strings.ToLower(nameFilter)) {
				matched = append(matched, p)
			}
		}
	}

	if len(matched) == 0 {
		msg := fmt.Sprintf("no process found matching pid=%d name=%q", targetPID, nameFilter)
		return errorResult(msg), nil
	}

	// Get all connections once and index by PID.
	allConns, _ := psnet.Connections("all")
	connsByPID := make(map[int32][]psnet.ConnectionStat)
	for _, c := range allConns {
		connsByPID[c.Pid] = append(connsByPID[c.Pid], c)
	}

	var reports []processReport
	for _, p := range matched {
		report := buildProcessReport(p, connsByPID[p.Pid])
		reports = append(reports, report)
	}

	// Sort by PID for deterministic output.
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].PID < reports[j].PID
	})

	type response struct {
		AnalyzedAt    time.Time        `json:"analyzed_at"`
		ProcessesFound int             `json:"processes_found"`
		GeoIPEnabled  bool             `json:"geoip_enabled"`
		Processes     []processReport  `json:"processes"`
	}

	out, err := json.Marshal(response{
		AnalyzedAt:     time.Now().UTC(),
		ProcessesFound: len(reports),
		GeoIPEnabled:   intel.Enabled(),
		Processes:      reports,
	})
	if err != nil {
		return errorResult("failed to encode response: " + err.Error()), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}

func buildProcessReport(p *process.Process, conns []psnet.ConnectionStat) processReport {
	report := processReport{
		PID:        p.Pid,
		AnalyzedAt: time.Now().UTC(),
	}

	report.Name, _ = p.Name()
	report.BinaryPath, _ = p.Exe()
	report.Cmdline, _ = p.Cmdline()
	report.Username, _ = p.Username()
	report.CreateTimeMs, _ = p.CreateTime()

	// Build parent chain (up to 4 levels).
	report.ParentChain = resolveParentChain(p, 4)

	// Enrich current connections with GeoIP.
	for _, c := range conns {
		remote := fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port)
		if c.Raddr.IP == "" || c.Raddr.IP == "0.0.0.0" || c.Raddr.IP == "::" {
			remote = "*"
		}
		ec := enrichedConn{
			Local:    fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port),
			Remote:   remote,
			State:    c.Status,
			Protocol: sockProtoName(c.Type),
		}
		if c.Raddr.IP != "" && c.Raddr.IP != "0.0.0.0" && c.Raddr.IP != "::" {
			if gi := intel.Lookup(c.Raddr.IP); gi != nil {
				ec.Country = gi.CountryCode
				ec.ASNOrg = gi.OrgName
				ec.GeoHighRisk = gi.IsHighRisk
			}
		}
		report.CurrentConnections = append(report.CurrentConnections, ec)
	}
	if report.CurrentConnections == nil {
		report.CurrentConnections = []enrichedConn{}
	}

	// Query history for matching flows.
	entries, _ := history.Query(history.QueryOpts{
		ProcessName: report.Name,
		MaxAge:      24 * time.Hour,
	})
	for _, e := range entries {
		report.HistoryFlowCount += e.FlowCount
	}

	return report
}

// resolveParentChain walks the parent PID chain up to maxDepth levels.
func resolveParentChain(p *process.Process, maxDepth int) []parentInfo {
	var chain []parentInfo
	cur := p
	for i := 0; i < maxDepth; i++ {
		ppid, err := cur.Ppid()
		if err != nil || ppid <= 1 {
			break
		}
		parent, err := process.NewProcess(ppid)
		if err != nil {
			break
		}
		name, _ := parent.Name()
		chain = append(chain, parentInfo{PID: ppid, Name: name})
		cur = parent
	}
	return chain
}

// sockProtoName converts gopsutil socket type to "TCP" / "UDP".
func sockProtoName(t uint32) string {
	switch t {
	case 1:
		return "TCP"
	case 2:
		return "UDP"
	default:
		return fmt.Sprintf("SOCK%d", t)
	}
}
