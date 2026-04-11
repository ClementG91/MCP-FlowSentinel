# =============================================================================
#  MCP-FlowSentinel — Build from source (Windows)
#  For most users, use the one-liner installer instead:
#    irm https://raw.githubusercontent.com/ClementG91/MCP-FlowSentinel/main/install.ps1 | iex
#
#  Use THIS script only if you want to compile from source (contributors, etc.)
#  Usage: Right-click -> "Run with PowerShell"   (recommended)
#      OR from an elevated PowerShell: .\build-windows.ps1
# =============================================================================

$ErrorActionPreference = "Stop"
$ProjectDir = $PSScriptRoot
$BinaryName = "mcp-flowsentinel.exe"
$BinaryPath = Join-Path $ProjectDir $BinaryName

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Step { param($m) Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "  [OK]   $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-Fail { param($m) Write-Host "  [FAIL] $m" -ForegroundColor Red }
function Write-Info { param($m) Write-Host "         $m" -ForegroundColor Gray }
function Abort      { param($m) Write-Fail $m; Read-Host "`nPress Enter to exit"; exit 1 }

Write-Host ""
Write-Host "  MCP-FlowSentinel — Build from source" -ForegroundColor Cyan
Write-Host "  https://github.com/ClementG91/MCP-FlowSentinel" -ForegroundColor DarkGray
Write-Host ""

# ── Step 0: Admin check ───────────────────────────────────────────────────────
Write-Step "Checking administrator rights..."
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warn "Not running as Administrator."
    Write-Info "Some steps (winget, PATH changes) may require elevation."
    Write-Info "Right-click build-windows.ps1 -> 'Run as administrator' for best results."
    $ans = Read-Host "  Continue anyway? [y/N]"
    if ($ans -notmatch "^[yY]") { exit 0 }
} else {
    Write-Ok "Running as Administrator."
}

# ── Step 1: Check / install Go ────────────────────────────────────────────────
Write-Step "Checking Go (>= 1.22)..."
$goOk = $false
try {
    $goRaw = & go version 2>&1
    if ($LASTEXITCODE -eq 0 -and $goRaw -match "go(\d+)\.(\d+)") {
        $maj = [int]$Matches[1]; $min = [int]$Matches[2]
        if ($maj -gt 1 -or ($maj -eq 1 -and $min -ge 22)) {
            $goOk = $true
            Write-Ok "$goRaw"
        } else {
            Write-Warn "Go $maj.$min found, but 1.22+ required."
        }
    }
} catch {}

if (-not $goOk) {
    Write-Warn "Go not found or too old — installing via winget..."
    try {
        winget install GoLang.Go --accept-package-agreements --accept-source-agreements --silent
        # Refresh PATH in current session
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH", "User")
        $goRaw = & go version 2>&1
        Write-Ok "Go installed: $goRaw"
    } catch {
        Abort "Go installation failed. Install manually: https://go.dev/dl/"
    }
}

# ── Step 2: Check / install GCC (MinGW) via winget ───────────────────────────
Write-Step "Checking GCC (required for CGO)..."
$gccPath = (Get-Command gcc -ErrorAction SilentlyContinue)?.Source
if (-not $gccPath) {
    # Search winget-installed WinLibs
    $candidate = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs*" `
        -Recurse -Filter "gcc.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($candidate) { $gccPath = $candidate.FullName }
}

if ($gccPath) {
    $gccVer = & $gccPath --version 2>&1 | Select-Object -First 1
    Write-Ok "GCC found: $gccVer"
    $gccDir = Split-Path $gccPath
    if ($env:PATH -notlike "*$gccDir*") { $env:PATH = "$gccDir;$env:PATH" }
} else {
    Write-Warn "GCC not found — installing WinLibs (MinGW-w64) via winget..."
    try {
        winget install BrechtSanders.WinLibs.POSIX.UCRT --accept-package-agreements --accept-source-agreements --silent
        # Locate freshly installed gcc.exe
        Start-Sleep -Seconds 2
        $candidate = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs*" `
            -Recurse -Filter "gcc.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($candidate) {
            $gccDir = Split-Path $candidate.FullName
            $env:PATH = "$gccDir;$env:PATH"
            Write-Ok "GCC installed: $gccDir"
        } else {
            Abort "GCC installed but not found. Restart PowerShell and re-run."
        }
    } catch {
        Abort "GCC installation failed: $_"
    }
}

# ── Step 3: Check Npcap runtime ───────────────────────────────────────────────
Write-Step "Checking Npcap runtime..."
$npcapOk = (Get-Service -Name "npcap" -ErrorAction SilentlyContinue) -or
           (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll")
if ($npcapOk) {
    Write-Ok "Npcap detected."
} else {
    Write-Warn "Npcap not installed. Required for network capture at runtime."
    Write-Host ""
    Write-Host "  Install Npcap (free, ~2 min):" -ForegroundColor Yellow
    Write-Host "    https://npcap.com/#download" -ForegroundColor Cyan
    Write-Host "  Check: 'Install Npcap in WinPcap API-compatible Mode'" -ForegroundColor Yellow
    Write-Host ""
    $ans = Read-Host "  Continue build anyway? [y/N]"
    if ($ans -notmatch "^[yY]") { exit 0 }
}

# ── Step 4: Locate / download Npcap SDK (headers for CGO) ────────────────────
Write-Step "Locating Npcap SDK (compile-time headers)..."

$sdkCandidates = @(
    $env:NPCAP_SDK,
    "C:\npcap-sdk",
    "C:\Program Files\Npcap\SDK",
    "C:\Program Files (x86)\Npcap\SDK",
    "$env:USERPROFILE\npcap-sdk",
    "$env:USERPROFILE\Downloads\npcap-sdk"
)

$NpcapSDK = $null
foreach ($p in $sdkCandidates) {
    if ($p -and (Test-Path (Join-Path $p "Include\pcap.h"))) {
        $NpcapSDK = $p
        break
    }
}

if ($NpcapSDK) {
    Write-Ok "Npcap SDK found: $NpcapSDK"
} else {
    Write-Warn "Npcap SDK not found — downloading automatically..."
    $sdkDest = "$env:USERPROFILE\npcap-sdk"
    $sdkZip  = "$env:TEMP\npcap-sdk.zip"
    try {
        Invoke-WebRequest -Uri "https://npcap.com/dist/npcap-sdk-1.13.zip" -OutFile $sdkZip -UseBasicParsing
        Expand-Archive -Path $sdkZip -DestinationPath $sdkDest -Force
        Remove-Item $sdkZip -ErrorAction SilentlyContinue
        $NpcapSDK = $sdkDest
        Write-Ok "Npcap SDK downloaded and extracted to: $NpcapSDK"
    } catch {
        Abort "Failed to download Npcap SDK: $_`nDownload manually from https://npcap.com/#download (SDK section) and extract to C:\npcap-sdk\"
    }
}

# ── Step 5: Build ─────────────────────────────────────────────────────────────
Write-Step "Building $BinaryName..."
Set-Location $ProjectDir

$version = "dev"
try {
    $v = & git describe --tags --always --dirty 2>$null
    if ($LASTEXITCODE -eq 0 -and $v) { $version = $v }
} catch {}

$env:CGO_ENABLED  = "1"
$env:CGO_CFLAGS   = "-I`"$(Join-Path $NpcapSDK 'Include')`""
$env:CGO_LDFLAGS  = "-L`"$(Join-Path $NpcapSDK 'Lib\x64')`""

try {
    & go build -buildvcs=false -trimpath -ldflags "-s -w -X main.version=$version" -o $BinaryName . 2>&1
    if ($LASTEXITCODE -ne 0) { throw "go build exited $LASTEXITCODE" }
} catch {
    Abort "Build failed: $_"
}
Write-Ok "Binary built: $BinaryPath"

# ── Step 6: Sanity check ──────────────────────────────────────────────────────
Write-Step "Running $BinaryName --check..."
Write-Host ""
& $BinaryPath --check
$checkCode = $LASTEXITCODE
Write-Host ""
if ($checkCode -eq 0) {
    Write-Ok "All checks passed."
} else {
    Write-Warn "Some checks failed (see above). Capture requires Administrator at runtime."
}

# ── Step 7: Configure Claude Desktop ─────────────────────────────────────────
Write-Step "Configuring Claude Desktop..."
$claudeDir  = Join-Path $env:APPDATA "Claude"
$claudeConf = Join-Path $claudeDir "claude_desktop_config.json"
if (-not (Test-Path $claudeDir)) { New-Item -ItemType Directory -Path $claudeDir | Out-Null }

$config = [PSCustomObject]@{}
if (Test-Path $claudeConf) {
    try { $config = Get-Content $claudeConf -Raw | ConvertFrom-Json } catch {}
}
if (-not ($config.PSObject.Properties.Name -contains "mcpServers")) {
    $config | Add-Member -MemberType NoteProperty -Name "mcpServers" -Value ([PSCustomObject]@{})
}
$config.mcpServers | Add-Member -MemberType NoteProperty -Name "flowsentinel" `
    -Value ([PSCustomObject]@{ command = $BinaryPath; args = @() }) -Force
$config | ConvertTo-Json -Depth 10 | Set-Content $claudeConf -Encoding UTF8
Write-Ok "Claude Desktop configured: $claudeConf"

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ============================================" -ForegroundColor Green
Write-Host "   Build complete! ($version)" -ForegroundColor Green
Write-Host "  ============================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Binary : $BinaryPath" -ForegroundColor White
Write-Host "  Config : $claudeConf" -ForegroundColor White
Write-Host ""
Write-Host "  Restart Claude Desktop as Administrator to activate FlowSentinel." -ForegroundColor Yellow
Write-Host ""
Read-Host "  Press Enter to close"
