//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// checkPrivileges verifies that the process is running as Administrator and
// prints actionable remediation instructions if not.
// Returns true when the process token is elevated.
func checkPrivileges(binaryPath string) bool {
	if isWindowsAdmin() {
		fmt.Println("[OK] Running as Administrator — full capture access.")
		return true
	}

	exePath, err := os.Executable()
	if err != nil {
		exePath = binaryPath
	}
	base := filepath.Base(exePath)

	fmt.Println("[WARN] Not running as Administrator.")
	fmt.Println("       Packet capture on Windows requires Administrator privileges.")
	fmt.Println()
	fmt.Println("       Option A — right-click the binary in Explorer:")
	fmt.Printf("         Right-click %s → 'Run as administrator'\n", base)
	fmt.Println()
	fmt.Println("       Option B — open an elevated PowerShell / CMD, then run:")
	fmt.Printf("         .\\%s --check\n", base)
	fmt.Println()
	fmt.Println("       Option C — create a scheduled task set to run as SYSTEM:")
	fmt.Println("         schtasks /create /tn FlowSentinel /tr \"<path>\" /sc onlogon /ru SYSTEM")
	fmt.Println()
	return false
}

// isWindowsAdmin returns true when the current process token has the
// TokenElevation flag set (UAC-elevated or running as SYSTEM).
// Uses only the standard-library syscall package — no external deps.
func isWindowsAdmin() bool {
	const (
		tokenQuery      = 0x0008
		tokenElevation  = 20 // TOKEN_INFORMATION_CLASS value
	)

	// kernel32!GetCurrentProcess returns a pseudo-handle; no Close needed.
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	hProcess, _, _ := getCurrentProcess.Call()

	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	openProcessToken := advapi32.NewProc("OpenProcessToken")
	getTokenInformation := advapi32.NewProc("GetTokenInformation")

	var hToken syscall.Handle
	r, _, _ := openProcessToken.Call(hProcess, tokenQuery, uintptr(unsafe.Pointer(&hToken)))
	if r == 0 {
		return false // cannot query — assume not elevated
	}
	defer syscall.CloseHandle(hToken) //nolint:errcheck

	// TokenElevation returns a DWORD (4 bytes).
	var elevation struct{ IsElevated uint32 }
	var retLen uint32
	r, _, _ = getTokenInformation.Call(
		uintptr(hToken),
		tokenElevation,
		uintptr(unsafe.Pointer(&elevation)),
		unsafe.Sizeof(elevation),
		uintptr(unsafe.Pointer(&retLen)),
	)
	return r != 0 && elevation.IsElevated != 0
}
