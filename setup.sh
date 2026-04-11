#!/usr/bin/env bash
# =============================================================================
#  MCP-FlowSentinel — One-command setup script
#  Supports: Ubuntu/Debian, Fedora/RHEL/CentOS, Arch, macOS (Homebrew)
#  Usage: ./setup.sh
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${CYAN}==>${NC} $*"; }
success() { echo -e "${GREEN}✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}WARN${NC} $*"; }
die()     { echo -e "${RED}ERROR${NC} $*" >&2; exit 1; }

BINARY="mcp-flowsentinel"
MIN_GO_MAJOR=1
MIN_GO_MINOR=22

# ─── OS detection ─────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
info "Detected OS: ${OS} / ${ARCH}"

# ─── Step 1: Install libpcap ──────────────────────────────────────────────────
install_libpcap() {
    info "Installing libpcap development headers..."

    case "${OS}" in
    Linux)
        if command -v apt-get &>/dev/null; then
            sudo apt-get update -qq
            sudo apt-get install -y libpcap-dev
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y libpcap-devel
        elif command -v yum &>/dev/null; then
            sudo yum install -y libpcap-devel
        elif command -v pacman &>/dev/null; then
            sudo pacman -Sy --noconfirm libpcap
        elif command -v zypper &>/dev/null; then
            sudo zypper install -y libpcap-devel
        else
            die "Unsupported Linux package manager. Please install libpcap-dev manually."
        fi
        ;;
    Darwin)
        if ! command -v brew &>/dev/null; then
            die "Homebrew not found. Install it from https://brew.sh then re-run this script."
        fi
        brew install libpcap 2>/dev/null || true
        ;;
    MINGW*|MSYS*|CYGWIN*)
        echo ""
        warn "Windows detected. Please install Npcap SDK manually:"
        warn "  1. Download from https://npcap.com/#download"
        warn "  2. Install Npcap runtime"
        warn "  3. Install Npcap SDK and set NPCAP_SDK env var"
        echo ""
        ;;
    *)
        die "Unsupported OS: ${OS}. Please install libpcap headers manually."
        ;;
    esac
    success "libpcap installed."
}

# Check if libpcap headers are already present
pcap_found=false
for p in /usr/include/pcap.h /usr/include/pcap/pcap.h /usr/local/include/pcap.h /opt/homebrew/include/pcap.h; do
    if [ -f "$p" ]; then
        pcap_found=true
        break
    fi
done

if [ "$pcap_found" = false ]; then
    install_libpcap
else
    success "libpcap headers already present."
fi

# ─── Step 2: Check / install Go ──────────────────────────────────────────────
install_go() {
    info "Installing Go ${MIN_GO_MAJOR}.${MIN_GO_MINOR}+..."
    local GO_VERSION="1.24.0"
    local GOARCH
    case "${ARCH}" in
        x86_64|amd64)  GOARCH="amd64" ;;
        arm64|aarch64) GOARCH="arm64" ;;
        *)             die "Unsupported architecture: ${ARCH}" ;;
    esac

    local GOOS
    case "${OS}" in
        Linux)  GOOS="linux" ;;
        Darwin) GOOS="darwin" ;;
        *)      die "Cannot auto-install Go on ${OS}. Please install Go ${MIN_GO_MAJOR}.${MIN_GO_MINOR}+ manually." ;;
    esac

    local TARBALL="go${GO_VERSION}.${GOOS}-${GOARCH}.tar.gz"
    local URL="https://go.dev/dl/${TARBALL}"

    info "Downloading ${URL}..."
    curl -fsSL "${URL}" -o "/tmp/${TARBALL}"
    sudo tar -C /usr/local -xzf "/tmp/${TARBALL}"
    rm -f "/tmp/${TARBALL}"

    export PATH="/usr/local/go/bin:${PATH}"
    success "Go installed at /usr/local/go."
}

check_go_version() {
    local GOBIN
    GOBIN="$(command -v go 2>/dev/null || echo '')"
    if [ -z "${GOBIN}" ]; then
        # Try common install paths
        for candidate in /usr/local/go/bin/go /usr/bin/go /opt/homebrew/bin/go; do
            if [ -x "${candidate}" ]; then
                GOBIN="${candidate}"
                export PATH="$(dirname "${GOBIN}"):${PATH}"
                break
            fi
        done
    fi

    if [ -z "${GOBIN}" ]; then
        return 1
    fi

    local VER
    VER="$(go version | awk '{print $3}' | sed 's/go//')"
    local MAJ MIN
    MAJ="$(echo "${VER}" | cut -d. -f1)"
    MIN="$(echo "${VER}" | cut -d. -f2)"

    if [ "${MAJ}" -gt "${MIN_GO_MAJOR}" ] || \
       { [ "${MAJ}" -eq "${MIN_GO_MAJOR}" ] && [ "${MIN}" -ge "${MIN_GO_MINOR}" ]; }; then
        return 0
    fi
    return 1
}

if check_go_version; then
    success "Go $(go version | awk '{print $3}') found."
else
    warn "Go not found or version < ${MIN_GO_MAJOR}.${MIN_GO_MINOR}."
    install_go
    if ! check_go_version; then
        die "Go installation failed. Please install Go ${MIN_GO_MAJOR}.${MIN_GO_MINOR}+ manually from https://go.dev/dl/"
    fi
fi

# ─── Step 3: Fetch Go module dependencies ─────────────────────────────────────
info "Fetching Go module dependencies..."
go mod tidy
go mod download
success "Dependencies downloaded."

# ─── Step 4: Build ────────────────────────────────────────────────────────────
info "Building ${BINARY}..."
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o "${BINARY}" .
success "Binary built: ./${BINARY}"

# ─── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  MCP-FlowSentinel is ready!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Add to your Claude Desktop config (claude_desktop_config.json):"
echo ""
echo '  "mcpServers": {'
echo '    "flowsentinel": {'
echo "      \"command\": \"$(pwd)/${BINARY}\","
echo '      "args": []'
echo '    }'
echo '  }'
echo ""
echo "  NOTE: Packet capture requires root/admin privileges."
echo "  Run the MCP server as root, or grant cap_net_raw:"
echo "    sudo setcap cap_net_raw,cap_net_admin+eip ./${BINARY}"
echo ""
