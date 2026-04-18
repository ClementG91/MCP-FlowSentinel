//go:build windows

package tools

import "github.com/shirou/gopsutil/v3/process"

// collectModulesUnix is a no-op stub on Windows where MemoryMapsStat has no
// Path field. Module enumeration on Windows requires EnumProcessModules (Win32).
func collectModulesUnix(_ *process.Process) []string { return nil }
