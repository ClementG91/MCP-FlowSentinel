//go:build linux

package tools

import (
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// collectModulesUnix reads /proc/<PID>/maps via gopsutil to return distinct
// shared-library paths. Only available on Linux where MemoryMapsStat has a
// Path field; other platforms return nil via scan_process_notlinux.go.
func collectModulesUnix(p *process.Process) []string {
	maps, err := p.MemoryMaps(true) // grouped=true: one entry per path
	if err != nil || maps == nil {
		return nil
	}
	seen := make(map[string]bool)
	var modules []string
	for _, m := range *maps {
		path := m.Path
		// Include only real file paths; skip anonymous mappings like
		// "", "[heap]", "[stack]", "[vdso]", "[vsyscall]", etc.
		if path == "" || strings.HasPrefix(path, "[") {
			continue
		}
		if !seen[path] {
			seen[path] = true
			modules = append(modules, path)
		}
	}
	return modules
}
