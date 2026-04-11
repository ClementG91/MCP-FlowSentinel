package aggregate

// FilterOptions controls which flows are included in tool output.
type FilterOptions struct {
	// MinScore excludes flows with SuspicionScore < MinScore. 0 = include all.
	MinScore float64
	// TopN limits results to the top N highest-score flows. 0 = no limit.
	TopN int
}

// Apply returns a filtered (and optionally truncated) slice of FlowRecords.
// The input slice is assumed to be pre-sorted descending by SuspicionScore.
func (f FilterOptions) Apply(flows []FlowRecord) []FlowRecord {
	if f.MinScore <= 0 && f.TopN <= 0 {
		return flows
	}

	out := flows[:0:0] // start with empty but same backing-array type
	for _, flow := range flows {
		if f.MinScore > 0 && flow.SuspicionScore < f.MinScore {
			break // sorted descending; once below threshold, all rest are too
		}
		out = append(out, flow)
	}

	if f.TopN > 0 && len(out) > f.TopN {
		out = out[:f.TopN]
	}
	return out
}

// RiskSummary counts flows by risk tier across the full (unfiltered) set.
type RiskSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// Summarise computes the risk tier counts from a slice of FlowRecords.
func Summarise(flows []FlowRecord) RiskSummary {
	var s RiskSummary
	for _, f := range flows {
		switch f.RiskLevel {
		case "CRITICAL":
			s.Critical++
		case "HIGH":
			s.High++
		case "MEDIUM":
			s.Medium++
		default:
			s.Low++
		}
	}
	return s
}
