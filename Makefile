##############################################################################
#  MCP-FlowSentinel — Makefile
#  Targets: build (default), install, clean, check-deps, tidy
##############################################################################

BINARY   := mcp-flowsentinel
GOPATH   ?= $(shell go env GOPATH)
GOBIN    ?= $(GOPATH)/bin
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -s -w -X main.version=$(VERSION)
GOFLAGS  := -trimpath

.PHONY: all build install clean check-deps tidy

all: check-deps build

##############################################################################
# Dependency checks
##############################################################################

check-deps:
	@echo "==> Checking Go version (need ≥ 1.22)..."
	@go version | awk '{split($$3,a,"go"); if (a[2]+0 < 1.22) {print "ERROR: Go 1.22+ required"; exit 1}}'

	@echo "==> Checking libpcap headers..."
	@test -f /usr/include/pcap.h \
	  || test -f /usr/include/pcap/pcap.h \
	  || test -f /usr/local/include/pcap.h \
	  || test -f /opt/homebrew/include/pcap.h \
	  || { \
	    echo ""; \
	    echo "ERROR: libpcap development headers not found."; \
	    echo ""; \
	    echo "  Linux  : sudo apt-get install libpcap-dev    (Debian/Ubuntu)"; \
	    echo "           sudo dnf install libpcap-devel      (Fedora/RHEL)"; \
	    echo "  macOS  : brew install libpcap"; \
	    echo "  Windows: install Npcap SDK from https://npcap.com/#download"; \
	    echo ""; \
	    exit 1; \
	  }

	@echo "==> All dependencies satisfied."

##############################################################################
# Build
##############################################################################

build:
	@echo "==> Building $(BINARY) ($(VERSION))..."
	CGO_ENABLED=1 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) .
	@echo "==> Binary ready: ./$(BINARY)"

##############################################################################
# Install to GOBIN
##############################################################################

install: check-deps
	@echo "==> Installing to $(GOBIN)/$(BINARY)..."
	CGO_ENABLED=1 go install $(GOFLAGS) -ldflags "$(LDFLAGS)" .
	@echo "==> Installed: $(GOBIN)/$(BINARY)"

##############################################################################
# Tidy / update modules
##############################################################################

tidy:
	@echo "==> Running go mod tidy..."
	go mod tidy
	@echo "==> Done."

##############################################################################
# Clean
##############################################################################

clean:
	@echo "==> Cleaning build artifacts..."
	rm -f $(BINARY)
	go clean -cache
	@echo "==> Clean."
