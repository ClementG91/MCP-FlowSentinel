//go:build !linux

package tools

import "github.com/shirou/gopsutil/v3/process"

// collectModulesUnix is a stub on non-Linux platforms. On macOS and BSD,
// gopsutil's MemoryMapsStat is an empty struct with no Path field; on Windows
// it is also empty. Module enumeration on those platforms requires
// platform-specific APIs (e.g. EnumProcessModules on Windows, vmmap on macOS).
func collectModulesUnix(_ *process.Process) []string { return nil }
