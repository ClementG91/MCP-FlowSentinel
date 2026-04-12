//go:build windows

package main

import "testing"

func TestIsWindowsAdmin_ReturnsBoolean(t *testing.T) {
	// Verify that the function runs without panicking and returns a bool.
	result := isWindowsAdmin()
	t.Logf("isWindowsAdmin() = %v", result)
}

func TestCheckPrivileges_ReturnsBoolean(t *testing.T) {
	// checkPrivileges prints to stdout but must not panic.
	result := checkPrivileges("mcp-flowsentinel-test.exe")
	t.Logf("checkPrivileges() = %v", result)
}
