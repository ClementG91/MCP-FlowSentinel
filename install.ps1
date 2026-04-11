# =============================================================================
#  MCP-FlowSentinel — Windows One-liner Installer
#  Usage:  irm https://raw.githubusercontent.com/ClementG91/MCP-FlowSentinel/main/install.ps1 | iex
#       OR: .\install.ps1
# =============================================================================
#  What this does:
#   1. Checks for Npcap (required runtime — cannot auto-install, proprietary)
#   2. Downloads the latest pre-built binary from GitHub Releases
#   3. Places it in %LOCALAPPDATA%\FlowSentinel\
#   4. Adds the install dir to your PATH (user scope)
#   5. Configures Claude Desktop automatically
# =============================================================================

$ErrorActionPreference = "Stop"
$Repo       = "ClementG91/MCP-FlowSentinel"
$BinaryName = "mcp-flowsentinel.exe"
$InstallDir = Join-Path $env:LOCALAPPDATA "FlowSentinel"

# ── Helpers ──────────────────────────────────────────────────────────────────
function Write-Step { param($m) Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-Fail { param($m) Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Write-Info { param($m) Write-Host "         $m" -ForegroundColor Gray }

Write-Host ""
Write-Host "  MCP-FlowSentinel Installer" -ForegroundColor Cyan
Write-Host "  https://github.com/$Repo" -ForegroundColor DarkGray
Write-Host ""

# ── Step 1: Npcap check ──────────────────────────────────────────────────────
Write-Step "Checking Npcap (required for packet capture)..."

$npcapOk = $false
if (Get-Service -Name "npcap" -ErrorAction SilentlyContinue) {
    $npcapOk = $true
    Write-Ok "Npcap service detected."
} elseif (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll") {
    $npcapOk = $true
    Write-Ok "Npcap DLL detected."
}

if (-not $npcapOk) {
    Write-Warn "Npcap is NOT installed."
    Write-Host ""
    Write-Host "  Npcap is required for network capture. It is free for personal use." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Install it now (takes ~2 minutes):" -ForegroundColor White
    Write-Host "    https://npcap.com/#download" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  During installation, check:" -ForegroundColor White
    Write-Host "    [x] Install Npcap in WinPcap API-compatible Mode" -ForegroundColor White
    Write-Host ""
    Write-Host "  After installing Npcap, re-run this installer." -ForegroundColor Yellow
    Write-Host ""
    $ans = Read-Host "  Continue anyway (binary will be installed, but capture will fail at runtime)? [y/N]"
    if ($ans -notmatch "^[yY]") {
        Write-Host "`n  Installer aborted. Install Npcap first, then re-run." -ForegroundColor Yellow
        exit 0
    }
}

# ── Step 2: Detect architecture ──────────────────────────────────────────────
Write-Step "Detecting architecture..."
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -eq "AMD64" -or $arch -eq "EM64T") {
    $assetName = "mcp-flowsentinel-windows-amd64.exe"
    Write-Ok "x86_64 (amd64) detected."
} elseif ($arch -eq "ARM64") {
    # No ARM64 Windows binary yet — fallback with warning
    $assetName = "mcp-flowsentinel-windows-amd64.exe"
    Write-Warn "ARM64 detected — using amd64 binary (requires x64 emulation, enabled by default on Windows 11)."
} else {
    Write-Fail "Unsupported architecture: $arch"
    Write-Info "Please open an issue: https://github.com/$Repo/issues"
    exit 1
}

# ── Step 3: Get latest release ───────────────────────────────────────────────
Write-Step "Fetching latest release from GitHub..."
try {
    $headers = @{ "User-Agent" = "mcp-flowsentinel-installer" }
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers
    $version = $release.tag_name
    Write-Ok "Latest release: $version"
} catch {
    Write-Fail "Could not fetch release info. Check your internet connection."
    Write-Info "Error: $_"
    exit 1
}

$asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
if (-not $asset) {
    Write-Fail "Binary '$assetName' not found in release $version."
    Write-Info "Available assets:"
    $release.assets | ForEach-Object { Write-Info "  $($_.name)" }
    Write-Info "Please open an issue: https://github.com/$Repo/issues"
    exit 1
}

# ── Step 4: Download ─────────────────────────────────────────────────────────
Write-Step "Downloading $assetName ($version)..."
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}
$BinaryPath = Join-Path $InstallDir $BinaryName

try {
    $tmp = [System.IO.Path]::GetTempFileName() + ".exe"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tmp -UseBasicParsing
    Move-Item -Path $tmp -Destination $BinaryPath -Force
    Write-Ok "Downloaded to: $BinaryPath"
} catch {
    Write-Fail "Download failed: $_"
    exit 1
}

# ── Step 5: Add to PATH ───────────────────────────────────────────────────────
Write-Step "Adding to PATH (user scope)..."
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$userPath;$InstallDir", "User")
    $env:PATH = "$env:PATH;$InstallDir"
    Write-Ok "Added '$InstallDir' to user PATH."
    Write-Info "Restart your terminal to use 'mcp-flowsentinel' from anywhere."
} else {
    Write-Ok "PATH already contains '$InstallDir'."
}

# ── Step 6: Quick sanity check ────────────────────────────────────────────────
Write-Step "Verifying binary..."
try {
    $v = & $BinaryPath --version 2>&1
    Write-Ok "$v"
} catch {
    Write-Warn "Could not run --version: $_"
}

# ── Step 7: Configure Claude Desktop ─────────────────────────────────────────
Write-Step "Configuring Claude Desktop..."

$claudeConfDir  = Join-Path $env:APPDATA "Claude"
$claudeConfFile = Join-Path $claudeConfDir "claude_desktop_config.json"

if (-not (Test-Path $claudeConfDir)) {
    New-Item -ItemType Directory -Path $claudeConfDir | Out-Null
}

if (Test-Path $claudeConfFile) {
    try {
        $config = Get-Content $claudeConfFile -Raw | ConvertFrom-Json
        Write-Info "Existing config found."
    } catch {
        Write-Warn "Existing config unreadable — starting fresh."
        $config = [PSCustomObject]@{}
    }
} else {
    $config = [PSCustomObject]@{}
    Write-Info "Creating new config file."
}

if (-not ($config.PSObject.Properties.Name -contains "mcpServers")) {
    $config | Add-Member -MemberType NoteProperty -Name "mcpServers" -Value ([PSCustomObject]@{})
}

$serverEntry = [PSCustomObject]@{ command = $BinaryPath; args = @() }
$config.mcpServers | Add-Member -MemberType NoteProperty -Name "flowsentinel" -Value $serverEntry -Force

$config | ConvertTo-Json -Depth 10 | Set-Content $claudeConfFile -Encoding UTF8
Write-Ok "Claude Desktop configured: $claudeConfFile"

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ============================================" -ForegroundColor Green
Write-Host "   MCP-FlowSentinel $version installed!" -ForegroundColor Green
Write-Host "  ============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Binary  : $BinaryPath" -ForegroundColor White
Write-Host "  Config  : $claudeConfFile" -ForegroundColor White
Write-Host ""
Write-Host "  NEXT STEPS:" -ForegroundColor Yellow
if (-not $npcapOk) {
    Write-Host "   1. Install Npcap: https://npcap.com/#download" -ForegroundColor Red
    Write-Host "   2. Restart Claude Desktop as Administrator" -ForegroundColor White
    Write-Host "   3. Ask Claude: 'list my network interfaces'" -ForegroundColor White
} else {
    Write-Host "   1. Restart Claude Desktop as Administrator" -ForegroundColor White
    Write-Host "      (Right-click Claude Desktop icon -> Run as administrator)" -ForegroundColor Gray
    Write-Host "   2. Ask Claude: 'list my network interfaces'" -ForegroundColor White
}
Write-Host ""
Write-Host "  To update later:" -ForegroundColor DarkGray
Write-Host "    mcp-flowsentinel --update" -ForegroundColor DarkGray
Write-Host ""
if ($Host.Name -eq "ConsoleHost") {
    Read-Host "  Press Enter to close"
}
