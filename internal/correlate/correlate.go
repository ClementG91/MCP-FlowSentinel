// Package correlate maps active network sockets to local processes using gopsutil.
package correlate

import (
	"fmt"
	"sync"

	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// ProcessInfo holds identifying data for a local process.
type ProcessInfo struct {
	PID        int32  `json:"pid"`
	Name       string `json:"name"`
	BinaryPath string `json:"binary_path,omitempty"`
	Cmdline    string `json:"cmdline,omitempty"`
	ParentPID  int32  `json:"parent_pid,omitempty"`
	ParentName string `json:"parent_name,omitempty"`
	Username   string `json:"username,omitempty"`
	CreateTime int64  `json:"create_time_ms,omitempty"`
}

// ConnectionInfo is a snapshot of one open socket.
type ConnectionInfo struct {
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	State    string `json:"state"`
	Protocol string `json:"protocol"`
}

// ProcessWithConns groups a process with all its open sockets.
type ProcessWithConns struct {
	PID         int32            `json:"pid"`
	Name        string           `json:"name"`
	BinaryPath  string           `json:"binary_path,omitempty"`
	Cmdline     string           `json:"cmdline,omitempty"`
	ParentPID   int32            `json:"parent_pid,omitempty"`
	ParentName  string           `json:"parent_name,omitempty"`
	Username    string           `json:"username,omitempty"`
	CreateTime  int64            `json:"create_time_ms,omitempty"`
	Connections []ConnectionInfo `json:"connections"`
}

// connKey is the internal four-tuple used to index established connections.
type connKey struct {
	localIP    string
	localPort  uint16
	remoteIP   string
	remotePort uint16
	proto      string
}

// SocketTable is a point-in-time snapshot of all open sockets → process mappings.
// Lookups are concurrent-safe via a read-write lock.
type SocketTable struct {
	mu          sync.RWMutex
	byConn      map[connKey]*ProcessInfo // exact four-tuple match
	byLocalPort map[string]*ProcessInfo  // "ip:port:proto" partial match
}

// ProcCache retains resolved process metadata across successive BuildSocketTable
// calls. Only PIDs that appear for the first time are resolved via gopsutil;
// PIDs that disappear from the connection list are pruned to prevent leaks.
//
// A single ProcCache should be created once (NewProcCache) and shared across
// all BuildSocketTableCached calls in the same monitoring session.
type ProcCache struct {
	mu    sync.Mutex
	procs map[int32]*ProcessInfo
}

// NewProcCache returns an initialised, empty ProcCache.
func NewProcCache() *ProcCache {
	return &ProcCache{procs: make(map[int32]*ProcessInfo, 64)}
}

// Size returns the number of PIDs currently held in the cache.
// Primarily used for observability and tests.
func (pc *ProcCache) Size() int {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return len(pc.procs)
}

// get returns a cached entry and whether it was found.
func (pc *ProcCache) get(pid int32) (*ProcessInfo, bool) {
	info, ok := pc.procs[pid]
	return info, ok
}

// set stores an entry in the cache.
func (pc *ProcCache) set(pid int32, info *ProcessInfo) {
	pc.procs[pid] = info
}

// pruneExcept removes every PID that is not in activePIDs.
func (pc *ProcCache) pruneExcept(activePIDs map[int32]struct{}) {
	for pid := range pc.procs {
		if _, alive := activePIDs[pid]; !alive {
			delete(pc.procs, pid)
		}
	}
}

// BuildSocketTable reads the current connection table via gopsutil and resolves
// each PID to its process metadata using a transient (per-call) process cache.
func BuildSocketTable() *SocketTable {
	return buildSocketTable(nil)
}

// BuildSocketTableCached is identical to BuildSocketTable but reuses process
// metadata for PIDs that were already resolved in a previous call, reducing
// gopsutil overhead significantly on repeated invocations.
func BuildSocketTableCached(cache *ProcCache) *SocketTable {
	return buildSocketTable(cache)
}

// buildSocketTable is the shared implementation. When cache is nil, a transient
// local process cache is used (matching the original BuildSocketTable behaviour).
func buildSocketTable(cache *ProcCache) *SocketTable {
	t := &SocketTable{
		byConn:      make(map[connKey]*ProcessInfo),
		byLocalPort: make(map[string]*ProcessInfo),
	}

	conns, err := psnet.Connections("all")
	if err != nil {
		return t // return empty table on error; caller handles gracefully
	}

	// localCache is the map passed to resolveProcess. When cache is provided we
	// copy its contents in, operate on the local map, then write back and prune.
	var localCache map[int32]*ProcessInfo
	if cache != nil {
		cache.mu.Lock()
		// Copy the current cache contents so we can work without holding the lock
		// across the (potentially slow) gopsutil calls.
		localCache = make(map[int32]*ProcessInfo, len(cache.procs)+16)
		for k, v := range cache.procs {
			localCache[k] = v
		}
		cache.mu.Unlock()
	} else {
		localCache = make(map[int32]*ProcessInfo, 64)
	}

	activePIDs := make(map[int32]struct{}, len(conns))

	for _, c := range conns {
		activePIDs[c.Pid] = struct{}{}
		info := resolveProcess(c.Pid, localCache)
		proto := protoName(c.Type)

		key := connKey{
			localIP:    c.Laddr.IP,
			localPort:  uint16(c.Laddr.Port),
			remoteIP:   c.Raddr.IP,
			remotePort: uint16(c.Raddr.Port),
			proto:      proto,
		}
		t.byConn[key] = info

		// Index by "ip:port:proto" for partial / asymmetric lookups.
		lk := fmt.Sprintf("%s:%d:%s", c.Laddr.IP, c.Laddr.Port, proto)
		t.byLocalPort[lk] = info

		// Also index the wildcard binding so LISTEN sockets match.
		if c.Laddr.IP != "0.0.0.0" && c.Laddr.IP != "::" {
			wk := fmt.Sprintf("0.0.0.0:%d:%s", c.Laddr.Port, proto)
			if _, exists := t.byLocalPort[wk]; !exists {
				t.byLocalPort[wk] = info
			}
		}
	}

	// Write back resolved entries and prune stale PIDs.
	if cache != nil {
		cache.mu.Lock()
		for pid, info := range localCache {
			cache.procs[pid] = info
		}
		cache.pruneExcept(activePIDs)
		cache.mu.Unlock()
	}

	return t
}

// Lookup tries to find a process for the given packet four-tuple.
// It tries an exact match in both directions, then falls back to local-port
// indexing.
func (t *SocketTable) Lookup(
	srcIP string, srcPort uint16,
	dstIP string, dstPort uint16,
	proto string,
) *ProcessInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Exact match: src is the local side.
	if info, ok := t.byConn[connKey{srcIP, srcPort, dstIP, dstPort, proto}]; ok {
		return info
	}
	// Exact match: dst is the local side (incoming).
	if info, ok := t.byConn[connKey{dstIP, dstPort, srcIP, srcPort, proto}]; ok {
		return info
	}

	// Partial matches using local-port index.
	candidates := [...]string{
		fmt.Sprintf("%s:%d:%s", srcIP, srcPort, proto),
		fmt.Sprintf("0.0.0.0:%d:%s", srcPort, proto),
		fmt.Sprintf("%s:%d:%s", dstIP, dstPort, proto),
		fmt.Sprintf("0.0.0.0:%d:%s", dstPort, proto),
	}
	for _, k := range candidates {
		if info, ok := t.byLocalPort[k]; ok {
			return info
		}
	}
	return nil
}

// GetAllConnections returns a map of PID → ProcessWithConns for every open
// socket on the system. Used by the get_process_map tool.
func GetAllConnections() (map[int32]*ProcessWithConns, error) {
	conns, err := psnet.Connections("all")
	if err != nil {
		return nil, fmt.Errorf("psnet.Connections: %w", err)
	}

	procCache := make(map[int32]*ProcessInfo, 64)
	result := make(map[int32]*ProcessWithConns, 32)

	for _, c := range conns {
		info := resolveProcess(c.Pid, procCache)

		if _, exists := result[c.Pid]; !exists {
			pwc := &ProcessWithConns{
				PID:        info.PID,
				Name:       info.Name,
				BinaryPath: info.BinaryPath,
				Cmdline:    info.Cmdline,
				ParentPID:  info.ParentPID,
				ParentName: info.ParentName,
				Username:   info.Username,
				CreateTime: info.CreateTime,
			}
			if c.Pid == 0 {
				pwc.Name = "kernel"
			}
			result[c.Pid] = pwc
		}

		local := fmt.Sprintf("%s:%d", c.Laddr.IP, c.Laddr.Port)
		remote := fmt.Sprintf("%s:%d", c.Raddr.IP, c.Raddr.Port)
		if c.Raddr.IP == "" || c.Raddr.IP == "0.0.0.0" || c.Raddr.IP == "::" {
			remote = "*"
		}

		result[c.Pid].Connections = append(result[c.Pid].Connections, ConnectionInfo{
			Local:    local,
			Remote:   remote,
			State:    c.Status,
			Protocol: protoName(c.Type),
		})
	}

	return result, nil
}

// resolveProcess looks up a PID in the cache or queries gopsutil for enriched
// process metadata (cmdline, parent, username, creation time).
func resolveProcess(pid int32, cache map[int32]*ProcessInfo) *ProcessInfo {
	if info, ok := cache[pid]; ok {
		return info
	}
	info := &ProcessInfo{PID: pid}
	if pid > 0 {
		if proc, err := process.NewProcess(pid); err == nil {
			info.Name, _ = proc.Name()
			info.BinaryPath, _ = proc.Exe()
			info.Cmdline, _ = proc.Cmdline()
			info.Username, _ = proc.Username()
			info.CreateTime, _ = proc.CreateTime()

			if ppid, err := proc.Ppid(); err == nil && ppid > 0 {
				info.ParentPID = ppid
				// Reuse the cache to avoid a redundant gopsutil call for the parent.
				parent := resolveProcessName(ppid, cache)
				info.ParentName = parent
			}
		}
	}
	cache[pid] = info
	return info
}

// resolveProcessName returns just the name for a PID, using the cache when
// possible. Unlike resolveProcess it does not recurse into the parent chain.
func resolveProcessName(pid int32, cache map[int32]*ProcessInfo) string {
	if info, ok := cache[pid]; ok {
		return info.Name
	}
	if proc, err := process.NewProcess(pid); err == nil {
		name, _ := proc.Name()
		// Store a minimal entry so the parent isn't re-queried for other children.
		cache[pid] = &ProcessInfo{PID: pid, Name: name}
		return name
	}
	return ""
}

// protoName converts a gopsutil socket type constant to a human-readable name.
// gopsutil uses syscall.SOCK_STREAM (1) and syscall.SOCK_DGRAM (2).
func protoName(sockType uint32) string {
	switch sockType {
	case 1:
		return "TCP"
	case 2:
		return "UDP"
	default:
		return fmt.Sprintf("SOCK%d", sockType)
	}
}
