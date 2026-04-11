#!/usr/bin/env bash
# =============================================================================
#  MCP-FlowSentinel — Build from source (macOS)
#  For most users, use the one-liner installer instead:
#    curl -fsSL https://raw.githubusercontent.com/ClementG91/MCP-FlowSentinel/main/install.sh | bash
#
#  Use THIS script only if you want to compile from source (contributors, etc.)
# =============================================================================

set -euo pipefail

BINARY_NAME="mcp-flowsentinel"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; GRAY='\033[0;90m'; RESET='\033[0m'

step() { echo -e "\n${CYAN}==> $*${RESET}"; }
ok()   { echo -e "  ${GREEN}[OK]${RESET}   $*"; }
warn() { echo -e "  ${YELLOW}[WARN]${RESET} $*"; }
fail() { echo -e "  ${RED}[FAIL]${RESET} $*"; exit 1; }
info() { echo -e "  ${GRAY}       $*${RESET}"; }

echo ""
echo -e "${CYAN}  MCP-FlowSentinel — Build from source (macOS)${RESET}"
echo -e "${GRAY}  https://github.com/ClementG91/MCP-FlowSentinel${RESET}"
echo ""

# ── Step 1: Check Xcode Command Line Tools ────────────────────────────────────
step "Checking Xcode Command Line Tools..."
if ! xcode-select -p &>/dev/null; then
    warn "Xcode CLT not installed — installing (this may take a few minutes)..."
    xcode-select --install
    read -r -p "  Press Enter after the installer finishes..."
fi
ok "Xcode CLT: $(xcode-select -p)"

# ── Step 2: Check Homebrew ────────────────────────────────────────────────────
step "Checking Homebrew..."
if ! command -v brew &>/dev/null; then
    warn "Homebrew not found — installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # Add brew to PATH for Apple Silicon
    if [[ -f /opt/homebrew/bin/brew ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    fi
fi
ok "Homebrew: $(brew --version | head -1)"

# ── Step 3: Check Go ──────────────────────────────────────────────────────────
step "Checking Go (>= 1.22)..."
if ! command -v go &>/dev/null; then
    warn "Go not found — installing via Homebrew..."
    brew install go
fi

GO_VERSION="$(go version | grep -oE '[0-9]+\.[0-9]+' | head -1)"
GO_MAJOR="$(echo "$GO_VERSION" | cut -d. -f1)"
GO_MINOR="$(echo "$GO_VERSION" | cut -d. -f2)"
if [[ $GO_MAJOR -lt 1 || ($GO_MAJOR -eq 1 && $GO_MINOR -lt 22) ]]; then
    warn "Go $GO_VERSION too old — upgrading..."
    brew upgrade go
fi
ok "$(go version)"

# ── Step 4: Check libpcap ─────────────────────────────────────────────────────
step "Checking libpcap..."
# macOS ships libpcap in /usr/lib; it's available by default.
if [[ -f /usr/lib/libpcap.dylib ]] || [[ -f /usr/local/lib/libpcap.dylib ]] || \
   [[ -f /opt/homebrew/lib/libpcap.dylib ]]; then
    ok "libpcap found."
else
    warn "libpcap not found — installing via Homebrew..."
    brew install libpcap
    ok "libpcap installed."
fi

# ── Step 5: Build ─────────────────────────────────────────────────────────────
step "Building $BINARY_NAME..."
cd "$PROJECT_DIR"

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo "dev")"

# Apple Silicon (arm64) or Intel (amd64)
ARCH="$(uname -m)"
if [[ "$ARCH" == "arm64" ]]; then
    GOARCH="arm64"
else
    GOARCH="amd64"
fi

CGO_ENABLED=1 GOARCH="$GOARCH" go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "$BINARY_NAME" .
ok "Binary built: $PROJECT_DIR/$BINARY_NAME  (version: $VERSION, arch: $GOARCH)"

# ── Step 6: Sanity check ──────────────────────────────────────────────────────
step "Running --check..."
echo ""
# On macOS, /dev/bpf* must be readable. Without root, a warning will appear.
"./$BINARY_NAME" --check || warn "Some checks failed (see above)."

# ── Step 7: Configure Claude Desktop ─────────────────────────────────────────
step "Configuring Claude Desktop..."
CLAUDE_CONF_DIR="$HOME/Library/Application Support/Claude"
CLAUDE_CONF_FILE="$CLAUDE_CONF_DIR/claude_desktop_config.json"
BINARY_ABS="$PROJECT_DIR/$BINARY_NAME"

if [[ ! -d "$CLAUDE_CONF_DIR" ]]; then
    warn "Claude Desktop not found at: $CLAUDE_CONF_DIR"
    info "Install Claude Desktop from: https://claude.ai/download"
    info "Then add this to $CLAUDE_CONF_FILE:"
    echo -e "${CYAN}{ \"mcpServers\": { \"flowsentinel\": { \"command\": \"$BINARY_ABS\", \"args\": [] } } }${RESET}"
else
    mkdir -p "$CLAUDE_CONF_DIR"
    if [[ -f "$CLAUDE_CONF_FILE" ]]; then
        cp "$CLAUDE_CONF_FILE" "$CLAUDE_CONF_FILE.bak"
        python3 - "$CLAUDE_CONF_FILE" "$BINARY_ABS" <<'PYEOF'
import sys, json
conf_file, binary = sys.argv[1], sys.argv[2]
with open(conf_file) as f:
    config = json.load(f)
config.setdefault("mcpServers", {})
config["mcpServers"]["flowsentinel"] = {"command": binary, "args": []}
with open(conf_file, "w") as f:
    json.dump(config, f, indent=2)
    f.write("\n")
PYEOF
    else
        python3 -c "
import json, sys
config = {'mcpServers': {'flowsentinel': {'command': sys.argv[1], 'args': []}}}
with open(sys.argv[2], 'w') as f:
    json.dump(config, f, indent=2)
    f.write('\n')
" "$BINARY_ABS" "$CLAUDE_CONF_FILE"
    fi
    ok "Claude Desktop configured: $CLAUDE_CONF_FILE"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}  ============================================${RESET}"
echo -e "${GREEN}   Build complete! ($VERSION)${RESET}"
echo -e "${GREEN}  ============================================${RESET}"
echo ""
echo -e "  Binary : ${BINARY_ABS}"
echo ""
echo -e "  Restart Claude Desktop to activate FlowSentinel."
echo ""
