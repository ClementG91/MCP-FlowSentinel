//go:build !windows

package main

import (
	"os"
	"testing"
)

func TestCheckPrivilegesMatchesEffectiveUser(t *testing.T) {
	if got, want := checkPrivileges("/usr/local/bin/mcp-flowsentinel"), os.Getuid() == 0; got != want {
		t.Fatalf("checkPrivileges() = %v, want %v for uid %d", got, want, os.Getuid())
	}
}
