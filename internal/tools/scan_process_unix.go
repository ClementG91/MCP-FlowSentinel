//go:build !windows

package tools

import (
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// collectModulesUnix reads /proc/<PID>/maps (Linux) or the mach vm region
// table (macOS) via gopsutil to return distinct shared-library paths.
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
