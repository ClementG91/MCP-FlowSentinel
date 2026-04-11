#!/usr/bin/env bash
# =============================================================================
#  MCP-FlowSentinel — Linux/macOS One-liner Installer
#  Usage:  curl -fsSL https://raw.githubusercontent.com/ClementG91/MCP-FlowSentinel/main/install.sh | bash
#       OR: ./install.sh
# =============================================================================
#  What this does:
#   1. Detects OS and architecture
#   2. Checks/installs libpcap (the only runtime dependency)
#   3. Downloads the latest pre-built binary from GitHub Releases
#   4. Places it in ~/.local/bin/ (or /usr/local/bin with sudo)
#   5. Configures Claude Desktop (if installed)
#   6. Optionally grants cap_net_raw on Linux (avoids running as root)
# =============================================================================

set -euo pipefail

REPO="ClementG91/MCP-FlowSentinel"
BINARY_NAME="mcp-flowsentinel"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; GRAY='\033[0;90m'; BOLD='\033[1m'; RESET='\033[0m'

step()  { echo -e "\n${CYAN}==> $*${RESET}"; }
ok()    { echo -e "  ${GREEN}[OK]${RESET}   $*"; }
warn()  { echo -e "  ${YELLOW}[WARN]${RESET} $*"; }
fail()  { echo -e "  ${RED}[FAIL]${RESET} $*"; }
info()  { echo -e "  ${GRAY}       $*${RESET}"; }

echo ""
echo -e "${BOLD}  MCP-FlowSentinel Installer${RESET}"
echo -e "${GRAY}  https://github.com/$REPO${RESET}"
echo ""

# ── Step 1: Detect OS / arch ─────────────────────────────────────────────────
step "Detecting platform..."

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64)  ASSET="mcp-flowsentinel-linux-amd64" ;;
      aarch64) ASSET="mcp-flowsentinel-linux-arm64" ;;
      *)
        fail "Unsupported architecture: $ARCH"
        info "Please open an issue: https://github.com/$REPO/issues"
        exit 1
        ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      x86_64)  ASSET="mcp-flowsentinel-darwin-amd64" ;;
      arm64)   ASSET="mcp-flowsentinel-darwin-arm64" ;;
      *)
        fail "Unsupported architecture: $ARCH"
        info "Please open an issue: https://github.com/$REPO/issues"
        exit 1
        ;;
    esac
    ;;
  *)
    fail "Unsupported OS: $OS. Use install.ps1 on Windows."
    exit 1
    ;;
esac

ok "Detected: $OS/$ARCH → $ASSET"

# ── Step 2: Check/install libpcap ────────────────────────────────────────────
step "Checking libpcap..."

PCAP_OK=false
if ldconfig -p 2>/dev/null | grep -q libpcap; then
    PCAP_OK=true
elif ls /usr/lib*/libpcap* /usr/local/lib/libpcap* 2>/dev/null | grep -q .; then
    PCAP_OK=true
elif [[ "$OS" == "Darwin" ]]; then
    # macOS ships libpcap in /usr/lib or via Homebrew
    if [[ -f /usr/lib/libpcap.dylib ]] || brew list libpcap &>/dev/null 2>&1; then
        PCAP_OK=true
    fi
fi

if $PCAP_OK; then
    ok "libpcap found."
else
    warn "libpcap not found — attempting to install..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq && sudo apt-get install -y libpcap0.8
        ok "Installed libpcap via apt."
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y libpcap
        ok "Installed libpcap via dnf."
    elif command -v yum &>/dev/null; then
        sudo yum install -y libpcap
        ok "Installed libpcap via yum."
    elif command -v pacman &>/dev/null; then
        sudo pacman -Sy --noconfirm libpcap
        ok "Installed libpcap via pacman."
    elif command -v brew &>/dev/null; then
        brew install libpcap
        ok "Installed libpcap via Homebrew."
    else
        warn "Could not auto-install libpcap."
        echo ""
        echo -e "  Install it manually:"
        echo -e "    Debian/Ubuntu : ${CYAN}sudo apt-get install libpcap0.8${RESET}"
        echo -e "    Fedora/RHEL   : ${CYAN}sudo dnf install libpcap${RESET}"
        echo -e "    Arch          : ${CYAN}sudo pacman -S libpcap${RESET}"
        echo -e "    macOS         : ${CYAN}brew install libpcap${RESET}"
        echo ""
        read -r -p "  Continue anyway? [y/N] " ans
        [[ "$ans" =~ ^[yY] ]] || { echo "  Aborted."; exit 0; }
    fi
fi

# ── Step 3: Fetch latest release ─────────────────────────────────────────────
step "Fetching latest release from GitHub..."

RELEASE_JSON="$(curl -fsSL -H "User-Agent: mcp-flowsentinel-installer" \
    "https://api.github.com/repos/$REPO/releases/latest")"

VERSION="$(echo "$RELEASE_JSON" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
DOWNLOAD_URL="$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "$ASSET\"" | sed -E 's/.*"browser_download_url": *"([^"]+)".*/\1/')"

if [[ -z "$VERSION" || -z "$DOWNLOAD_URL" ]]; then
    fail "Could not parse release info. Check your internet connection."
    info "API response: $RELEASE_JSON"
    exit 1
fi
ok "Latest release: $VERSION"

# ── Step 4: Download binary ───────────────────────────────────────────────────
step "Downloading $ASSET ($VERSION)..."

TMP_BIN="$(mktemp)"
curl -fsSL --progress-bar -o "$TMP_BIN" "$DOWNLOAD_URL"
chmod +x "$TMP_BIN"

# Verify it runs
if ! "$TMP_BIN" --version &>/dev/null; then
    fail "Downloaded binary failed to run. It may be the wrong architecture."
    rm -f "$TMP_BIN"
    exit 1
fi
ok "Binary verified: $("$TMP_BIN" --version)"

# ── Step 5: Install ───────────────────────────────────────────────────────────
step "Installing to $INSTALL_DIR..."

mkdir -p "$INSTALL_DIR"
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"
mv "$TMP_BIN" "$BINARY_PATH"
ok "Installed: $BINARY_PATH"

# Add to PATH if needed
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    warn "'$INSTALL_DIR' is not in your PATH."

    SHELL_RC=""
    if [[ -n "${ZSH_VERSION:-}" ]] || [[ "$SHELL" == */zsh ]]; then
        SHELL_RC="$HOME/.zshrc"
    elif [[ -n "${BASH_VERSION:-}" ]] || [[ "$SHELL" == */bash ]]; then
        SHELL_RC="$HOME/.bashrc"
    fi

    if [[ -n "$SHELL_RC" ]]; then
        echo "" >> "$SHELL_RC"
        echo "# mcp-flowsentinel" >> "$SHELL_RC"
        echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$SHELL_RC"
        info "Added to $SHELL_RC — restart your terminal or run: source $SHELL_RC"
    else
        info "Add this to your shell config: export PATH=\"\$PATH:$INSTALL_DIR\""
    fi
fi

# ── Step 6: Linux — grant cap_net_raw (avoid needing sudo at runtime) ─────────
if [[ "$OS" == "Linux" ]]; then
    step "Granting cap_net_raw capability (avoids sudo for capture)..."
    if command -v setcap &>/dev/null; then
        if sudo setcap cap_net_raw,cap_net_admin+eip "$BINARY_PATH" 2>/dev/null; then
            ok "cap_net_raw granted — no sudo needed at runtime."
        else
            warn "Could not set capabilities. You may need to run with sudo."
            info "To fix later: sudo setcap cap_net_raw,cap_net_admin+eip $BINARY_PATH"
        fi
    else
        warn "setcap not found. Install libcap2-bin: sudo apt-get install libcap2-bin"
        info "Then run: sudo setcap cap_net_raw,cap_net_admin+eip $BINARY_PATH"
    fi
fi

# ── Step 7: Configure Claude Desktop ─────────────────────────────────────────
step "Configuring Claude Desktop..."

# Detect Claude Desktop config location
if [[ "$OS" == "Darwin" ]]; then
    CLAUDE_CONF_DIR="$HOME/Library/Application Support/Claude"
elif [[ "$OS" == "Linux" ]]; then
    CLAUDE_CONF_DIR="$HOME/.config/Claude"
fi

CLAUDE_CONF_FILE="$CLAUDE_CONF_DIR/claude_desktop_config.json"

if [[ ! -d "$CLAUDE_CONF_DIR" ]]; then
    warn "Claude Desktop config directory not found at: $CLAUDE_CONF_DIR"
    info "Is Claude Desktop installed? Get it at: https://claude.ai/download"
    info "To configure manually, add this to $CLAUDE_CONF_FILE:"
    echo ""
    echo -e "${CYAN}{
  \"mcpServers\": {
    \"flowsentinel\": {
      \"command\": \"$BINARY_PATH\",
      \"args\": []
    }
  }
}${RESET}"
    echo ""
else
    mkdir -p "$CLAUDE_CONF_DIR"

    if [[ -f "$CLAUDE_CONF_FILE" ]]; then
        # Backup existing config
        cp "$CLAUDE_CONF_FILE" "$CLAUDE_CONF_FILE.bak"
        info "Backed up existing config to $CLAUDE_CONF_FILE.bak"

        # Inject mcpServers entry using Python (available on all platforms)
        python3 - "$CLAUDE_CONF_FILE" "$BINARY_PATH" <<'PYEOF'
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
        ok "Claude Desktop configured: $CLAUDE_CONF_FILE"
    else
        # Create fresh config
        python3 -c "
import json, sys
config = {'mcpServers': {'flowsentinel': {'command': sys.argv[1], 'args': []}}}
with open(sys.argv[2], 'w') as f:
    json.dump(config, f, indent=2)
    f.write('\n')
" "$BINARY_PATH" "$CLAUDE_CONF_FILE"
        ok "Created Claude Desktop config: $CLAUDE_CONF_FILE"
    fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  ============================================${RESET}"
echo -e "${GREEN}${BOLD}   MCP-FlowSentinel $VERSION installed!${RESET}"
echo -e "${GREEN}${BOLD}  ============================================${RESET}"
echo ""
echo -e "  Binary  : ${BOLD}$BINARY_PATH${RESET}"
echo ""
echo -e "  ${BOLD}NEXT STEPS:${RESET}"
if [[ "$OS" == "Darwin" ]]; then
    echo -e "   1. Restart Claude Desktop"
    echo -e "   2. Ask Claude: 'list my network interfaces'"
else
    echo -e "   1. Restart Claude Desktop"
    echo -e "   2. Ask Claude: 'list my network interfaces'"
fi
echo ""
echo -e "  ${GRAY}To update: mcp-flowsentinel --update${RESET}"
echo ""
