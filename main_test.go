package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintUsageDocumentsSupportedCommands(t *testing.T) {
	var out bytes.Buffer
	printUsage(&out)
	for _, flag := range []string{
		"--daemon", "--check", "--init-config", "--validate-config",
		"--test-alert", "--update", "--version", "--help", "--config",
	} {
		if !strings.Contains(out.String(), flag) {
			t.Errorf("usage does not document %s", flag)
		}
	}
}
