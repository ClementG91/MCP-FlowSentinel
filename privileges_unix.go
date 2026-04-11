//go:build !windows

package main

import (
	"fmt"
	"os"
	"runtime"
)

// checkPrivileges verifies that the process has sufficient OS privileges for
// raw-packet capture and prints actionable remediation instructions if not.
// Returns true when all privilege requirements are satisfied.
func checkPrivileges(binaryPath string) bool {
	if os.Getuid() == 0 {
		fmt.Println("[OK] Running as root — full capture access.")
		return true
	}

	fmt.Println("[WARN] Not running as root.")
	fmt.Println("       Raw-packet capture requires elevated privileges.")

	switch runtime.GOOS {
	case "linux":
		fmt.Println()
		fmt.Println("       Option A — grant capabilities (recommended, no full root):")
		fmt.Printf("         sudo setcap cap_net_raw,cap_net_admin+eip %s\n", binaryPath)
		fmt.Println()
		fmt.Println("       Option B — run as root:")
		fmt.Printf("         sudo %s\n", binaryPath)
	case "darwin":
		fmt.Println()
		fmt.Println("       Run the server as root:")
		fmt.Printf("         sudo %s\n", binaryPath)
		fmt.Println()
		fmt.Println("       Or allow non-root capture (macOS 10.14+):")
		fmt.Println("         sudo chmod +r /dev/bpf*")
	default:
		fmt.Printf("\n       Please run as root: sudo %s\n", binaryPath)
	}
	fmt.Println()
	return false
}
