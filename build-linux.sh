#!/usr/bin/env bash
# =============================================================================
#  MCP-FlowSentinel — Build from source (Linux)
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
echo -e "${CYAN}  MCP-FlowSentinel — Build from source${RESET}"
echo -e "${GRAY}  https://github.com/ClementG91/MCP-FlowSentinel${RESET}"
echo ""

# ── Step 1: Check Go ──────────────────────────────────────────────────────────
step "Checking Go (>= 1.22)..."
if ! command -v go &>/dev/null; then
    fail "Go is not installed. Install it from https://go.dev/dl/ or via your package manager:
    Debian/Ubuntu : sudo apt-get install golang-go
    Fedora        : sudo dnf install golang
    Arch          : sudo pacman -S go
    macOS         : brew install go"
fi

GO_VERSION="$(go version | grep -oP '\d+\.\d+' | head -1)"
GO_MAJOR="$(echo "$GO_VERSION" | cut -d. -f1)"
GO_MINOR="$(echo "$GO_VERSION" | cut -d. -f2)"
if [[ $GO_MAJOR -lt 1 || ($GO_MAJOR -eq 1 && $GO_MINOR -lt 22) ]]; then
    fail "Go $GO_VERSION found, but 1.22+ required. Update: https://go.dev/dl/"
fi
ok "$(go version)"

# ── Step 2: Check / install libpcap-dev ───────────────────────────────────────
step "Checking libpcap (build headers)..."
PCAP_HEADER=""
for p in /usr/include/pcap.h /usr/local/include/pcap.h /usr/include/x86_64-linux-gnu/pcap.h; do
    [[ -f "$p" ]] && { PCAP_HEADER="$p"; break; }
done

if [[ -n "$PCAP_HEADER" ]]; then
    ok "libpcap headers found: $PCAP_HEADER"
else
    warn "libpcap dev headers not found — installing..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y libpcap-dev
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y libpcap-devel
    elif command -v yum &>/dev/null; then
        sudo yum install -y libpcap-devel
    elif command -v pacman &>/dev/null; then
        sudo pacman -Sy --noconfirm libpcap
    else
        fail "Cannot auto-install libpcap. Install manually:
    Debian/Ubuntu : sudo apt-get install libpcap-dev
    Fedora/RHEL   : sudo dnf install libpcap-devel
    Arch          : sudo pacman -S libpcap"
    fi
    ok "libpcap dev headers installed."
fi

# ── Step 3: Build ─────────────────────────────────────────────────────────────
step "Building $BINARY_NAME..."
cd "$PROJECT_DIR"

VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo "dev")"
CGO_ENABLED=1 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "$BINARY_NAME" .
ok "Binary built: $PROJECT_DIR/$BINARY_NAME  (version: $VERSION)"

# ── Step 4: Grant cap_net_raw ─────────────────────────────────────────────────
step "Granting cap_net_raw (avoids sudo for capture)..."
if command -v setcap &>/dev/null; then
    if sudo setcap cap_net_raw,cap_net_admin+eip "./$BINARY_NAME" 2>/dev/null; then
        ok "cap_net_raw granted — no sudo needed at runtime."
    else
        warn "Could not set capabilities. You may need to run with sudo."
        info "Fix later: sudo setcap cap_net_raw,cap_net_admin+eip $PROJECT_DIR/$BINARY_NAME"
    fi
else
    warn "setcap not found. Install libcap2-bin: sudo apt-get install libcap2-bin"
fi

# ── Step 5: Sanity check ──────────────────────────────────────────────────────
step "Running --check..."
echo ""
"./$BINARY_NAME" --check || warn "Some checks failed (see above)."

# ── Step 6: Configure Claude Desktop ─────────────────────────────────────────
step "Configuring Claude Desktop..."
CLAUDE_CONF_DIR="$HOME/.config/Claude"
CLAUDE_CONF_FILE="$CLAUDE_CONF_DIR/claude_desktop_config.json"
BINARY_ABS="$PROJECT_DIR/$BINARY_NAME"

if [[ ! -d "$CLAUDE_CONF_DIR" ]]; then
    warn "Claude Desktop config dir not found ($CLAUDE_CONF_DIR)."
    info "Is Claude Desktop installed? Get it at: https://claude.ai/download"
    info "Manual config snippet:"
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
