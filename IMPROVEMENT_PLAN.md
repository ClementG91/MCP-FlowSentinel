# MCP-FlowSentinel — Plan d'amélioration expert
> Auteur : audit senior cyber/réseau — Avril 2026  
> Base : état actuel post-Phase-1 (322 tests, 0 races)

---

## Vue d'ensemble des priorités

| Phase | Titre | Impact sécurité | Complexité | Effort estimé |
|-------|-------|----------------|------------|---------------|
| **2.1** | TCP Stream Reassembly | CRITIQUE | Élevée | ~3 jours |
| **2.2** | HTTP/1.1 Layer Parsing | CRITIQUE | Moyenne | ~2 jours |
| **2.3** | JA3 Dynamic Threat Feed | ÉLEVÉ | Faible | ~1 jour |
| **2.4** | Multi-interface Capture | ÉLEVÉ | Moyenne | ~1.5 jours |
| **2.5** | TLS Certificate Analysis | ÉLEVÉ | Moyenne | ~2 jours |
| **2.6** | Prometheus Metrics | MOYEN | Faible | ~0.5 jour |
| **2.7** | HTTP/2 & gRPC Detection | MOYEN | Élevée | ~3 jours |
| **2.8** | History Compression + Index | MOYEN | Faible | ~1 jour |
| **2.9** | Alerting Rate-Limit + HMAC | MOYEN | Faible | ~0.5 jour |
| **2.10** | IPv6 Extension Headers | FAIBLE | Moyenne | ~1 jour |

---

## Phase 2.1 — TCP Stream Reassembly

### Pourquoi c'est critique

Un ClientHello TLS peut légalement être fragmenté sur plusieurs segments TCP.
C'est rare sur LAN (MTU 1500 → ClientHello ≤ 1460 octets) mais systématique sur :
- VPN/tunnels (MTU réduit à 1280 ou moins)
- Réseaux mobiles (segmentation radio)
- C2 avec profils Malleable qui padding leur ClientHello volontairement

Actuellement, `parsePacket()` lit le payload du **premier** paquet du segment transport.
Si le ClientHello est coupé, `extractTLSSNI()` retourne `""` et `ja3.Fingerprint()` retourne `""` — flow invisible pour JA3.

### Solution technique

`gopacket v1.1.19` inclut le package `github.com/google/gopacket/tcpassembly` (RFC 793 stream reassembly, out-of-order handling, timeout-based flush). Il n'est simplement pas importé actuellement.

#### Architecture proposée

```
capture.go
 └─ CapturePackets()                 ← inchangé (raw packets)
    │
    ▼
reassembly/reassembler.go           ← NOUVEAU package
 ├─ TLSStreamFactory                ← implémente tcpassembly.StreamFactory
 │   └─ New() → *TLSStream         ← créé pour chaque new TCP stream
 ├─ TLSStream                       ← implémente tcpassembly.Stream
 │   ├─ buf []byte                  ← buffer circulaire borné (max 8 KB)
 │   ├─ Reassembled([]byte)         ← appelé par tcpassembly à chaque chunk
 │   └─ ReassemblyComplete()        ← flush final
 └─ Reassembler                     ← wrapper autour de tcpassembly.Assembler
     ├─ Add(pkt gopacket.Packet)    ← injecte chaque paquet TCP
     └─ FlushExpired()              ← appelé périodiquement (500 ms)
```

#### Changements de code

**Nouveau fichier : `internal/reassembly/reassembler.go`**

```go
package reassembly

import (
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/tcpassembly"
    "github.com/ClementG91/MCP-FlowSentinel/internal/ja3"
)

const maxStreamBuf = 8 * 1024 // 8 KB suffit pour tout ClientHello connu

type SNIResult struct {
    SrcIP, DstIP string
    SrcPort, DstPort uint16
    SNI     string
    JA3Hash string
}

type TLSStreamFactory struct {
    out chan<- SNIResult
}

type TLSStream struct {
    buf  []byte
    done bool
    meta SNIResult
    out  chan<- SNIResult
}

func (f *TLSStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
    s := &TLSStream{out: f.out}
    s.meta.SrcIP   = net.Src().String()
    s.meta.DstIP   = net.Dst().String()
    s.meta.SrcPort = uint16(binary.BigEndian.Uint16(transport.Src().Raw()))
    s.meta.DstPort = uint16(binary.BigEndian.Uint16(transport.Dst().Raw()))
    return s
}

func (s *TLSStream) Reassembled(rs []tcpassembly.ReassemblyInfo) {
    if s.done { return }
    for _, r := range rs {
        remaining := maxStreamBuf - len(s.buf)
        if remaining <= 0 { break }
        if len(r.Bytes) > remaining {
            s.buf = append(s.buf, r.Bytes[:remaining]...)
        } else {
            s.buf = append(s.buf, r.Bytes...)
        }
    }
    // Try to extract SNI as soon as we have enough bytes.
    if sni := extractTLSSNI(s.buf); sni != "" {
        s.meta.SNI = sni
        s.meta.JA3Hash = ja3.Fingerprint(s.buf)
        s.out <- s.meta
        s.done = true
    }
}

func (s *TLSStream) ReassemblyComplete() { /* nothing */ }
```

**Intégration dans `capture.go`** :

```go
// drainPackets() — ajouter après src.NextPacket():
if pkt.TransportLayer() != nil {
    if tcp, ok := pkt.TransportLayer().(*layers.TCP); ok {
        assembler.Assemble(pkt.NetworkLayer().NetworkFlow(), tcp)
    }
}
// SNI results merged asynchronously via channel back into PacketEvent stream
```

**Critères de complétion** :
- [ ] `go test -race ./internal/reassembly/...` vert
- [ ] Test avec pcap contenant un ClientHello fragmenté (ex: openssl s_client sur MTU=576)
- [ ] Mémoire bornée : buffer max 8 KB par stream, flush après 5 s d'inactivité
- [ ] Pas de goroutine leak (vérifier avec goleak)

---

## Phase 2.2 — HTTP/1.1 Layer Parsing

### Pourquoi c'est critique

Cobalt Strike par défaut utilise HTTP GET/POST sur port 80 avec :
- `User-Agent: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko`
- URI aléatoire : `/jquery-3.3.1.min.js`, `/favicon.ico`, `/updates.rss`
- Réponses vides ou HTML minimal en retour

Actuellement invisible. Avec HTTP parsing, le User-Agent fixe de CS serait détecté immédiatement.

### Solution technique

Pas besoin d'un parser HTTP complet. Un parser de **headers HTTP/1.1** suffit.

**Nouveau fichier : `internal/capture/http.go`**

```go
package capture

import (
    "bufio"
    "bytes"
    "net/http"
    "strings"
)

type HTTPInfo struct {
    IsRequest   bool
    Method      string // GET, POST, CONNECT...
    URI         string
    Host        string
    UserAgent   string
    ContentType string
    StatusCode  int    // 0 if request
}

// extractHTTPInfo tries to parse the TCP payload as HTTP/1.1 request or response.
// Returns nil if the payload is not HTTP (e.g. binary, TLS).
func extractHTTPInfo(payload []byte) *HTTPInfo {
    if len(payload) < 14 { // "GET / HTTP/1.1" = 14 bytes minimum
        return nil
    }
    // Fast pre-check: HTTP requests start with a known method.
    // HTTP responses start with "HTTP/".
    isReq  := isHTTPRequestStart(payload)
    isResp := !isReq && bytes.HasPrefix(payload, []byte("HTTP/"))
    if !isReq && !isResp {
        return nil
    }

    if isReq {
        req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
        if err != nil { return nil }
        return &HTTPInfo{
            IsRequest: true,
            Method:    req.Method,
            URI:       req.URL.RequestURI(),
            Host:      req.Host,
            UserAgent: req.UserAgent(),
        }
    }
    resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), nil)
    if err != nil { return nil }
    return &HTTPInfo{
        IsRequest:   false,
        StatusCode:  resp.StatusCode,
        ContentType: resp.Header.Get("Content-Type"),
    }
}

var httpMethods = [][]byte{
    []byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
    []byte("HEAD "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
    []byte("TRACE "),
}

func isHTTPRequestStart(b []byte) bool {
    for _, m := range httpMethods {
        if bytes.HasPrefix(b, m) { return true }
    }
    return false
}
```

**Ajout au `PacketEvent`** :
```go
HTTPMethod    string // "GET", "POST", "CONNECT", "" if not HTTP
HTTPHost      string // Host header
HTTPUserAgent string // User-Agent header  
HTTPURI       string // request URI (first 256 chars)
```

**Scoring HTTP dans `aggregate.go`** :

```go
// ── HTTP layer analysis ─────────────────────────────────────────────────────
if !cfg.DisableHTTPScoring && rec.HTTPMethod != "" {
    // CONNECT tunneling over HTTP (proxy abuse)
    if rec.HTTPMethod == "CONNECT" {
        add(2.0, "HTTP CONNECT tunnel — potential proxy/C2 channel")
    }
    // Known-malicious User-Agents
    if ua := rec.HTTPUserAgent; ua != "" {
        if isKnownBadUserAgent(ua) {
            add(3.0, fmt.Sprintf("suspicious HTTP User-Agent: %q", ua))
        }
        if ua == "" || len(ua) < 5 {
            add(1.0, "empty or minimal HTTP User-Agent")
        }
    }
    // HTTP on non-standard port (not 80, 8080, 8000, 8888)
    if !standardHTTPPorts[key.DstPort] && key.DstPort != 443 {
        add(1.5, fmt.Sprintf("HTTP traffic on non-standard port %d", key.DstPort))
    }
    // High-entropy URI (C2 check-in pattern)
    if isHighEntropyURI(rec.HTTPURI) {
        add(1.5, fmt.Sprintf("high-entropy HTTP URI: %s", truncate(rec.HTTPURI, 60)))
    }
}
```

**Known-bad User-Agents à couvrir** (non exhaustif, configurable) :
- Cobalt Strike defaults : `Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko`
- Sliver defaults : `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`
- Empire : `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko`
- Metasploit Meterpreter HTTP : `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
- Vide / length < 5

**Critères de complétion** :
- [ ] HTTP request parsing ne panics pas sur payload binaire malformé
- [ ] `go test -race ./internal/capture/...` vert
- [ ] Test avec pcap contenant Cobalt Strike default profile HTTP
- [ ] Pas de faux positifs sur trafic curl/wget légitime (User-Agent scoring séparable)

---

## Phase 2.3 — JA3 Dynamic Threat Intelligence Feed

### Pourquoi c'est élevé

Les 15 hashes actuels couvrent 2018-2022. En 2024-2026 :
- **Sliver** avec profils custom change son JA3 à chaque build
- **Brute Ratel C4** a plusieurs profils documentés post-v1.2
- **Havoc Framework** avec malleable comms change les cipher suites

Sources publiques et gratuites disponibles :
1. `https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv` — abuse.ch SSL blacklist (mis à jour daily)
2. `https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv` — Salesforce JA3 DB
3. Fichier local override `~/.config/mcp-flowsentinel/ja3_custom.csv`

### Solution technique

**Nouveau fichier : `internal/ja3/feed.go`**

```go
package ja3

import (
    "bufio"
    "encoding/csv"
    "fmt"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
)

// feedEntry is a hash from a remote threat intel feed.
type feedEntry struct {
    Hash        string
    Description string
    Source      string // "abuse.ch", "salesforce", "custom"
}

var (
    feedMu      sync.RWMutex
    feedEntries map[string]feedEntry // hash → entry
    feedPath    string               // local cache file
)

func init() {
    home, _ := os.UserHomeDir()
    feedPath = filepath.Join(home, ".cache", "mcp-flowsentinel", "ja3_feed.json")
    loadFeedFromDisk()
}

// UpdateFeed fetches feeds from configured URLs, merges with built-in list,
// and persists to disk. Safe to call from a background goroutine.
func UpdateFeed(feedURLs []string) error { ... }

// LookupWithFeed checks the hash against built-in list + feed + custom hashes.
func LookupWithFeed(hash string, extraHashes []string) (family string, ok bool) {
    // 1. Built-in
    if f, found := knownBadHashes[hash]; found { return f, true }
    // 2. Dynamic feed
    feedMu.RLock()
    if e, found := feedEntries[hash]; found { feedMu.RUnlock(); return e.Description, true }
    feedMu.RUnlock()
    // 3. Config custom
    return LookupCustom(hash, extraHashes)
}
```

**Config additions** :
```yaml
# ja3_feed section
ja3_feed:
  enabled: true
  update_interval_hours: 24
  urls:
    - "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
  local_file: ""  # optional: path to custom CSV with hash,description columns
```

**Ajout d'un feed updater dans `daemon.go`** :
```go
// En arrière-plan, refresh JA3 feed toutes les 24h
go func() {
    ticker := time.NewTicker(time.Duration(cfg.JA3Feed.UpdateIntervalHours) * time.Hour)
    for range ticker.C {
        if err := ja3.UpdateFeed(cfg.JA3Feed.URLs); err != nil {
            log.Printf("ja3 feed update failed: %v", err)
        }
    }
}()
```

**Aussi : ajouter JA3S (server fingerprint)** :

Actuellement seul le ClientHello est fingerprinted. Le ServerHello permet de détecter
les serveurs C2 qui répondent avec des cipher suites inhabituelles.

JA3S = `SSLVersion,Cipher,SSLExtension`

```go
// Dans extractTLSSNI() ou nouveau extractTLSServerHello() :
// Record type 0x16, handshake type 0x02 (ServerHello)
// Extraire: version + cipher suite sélectionnée + extensions présentes
func ExtractJA3S(payload []byte) string { ... }
```

**Critères de complétion** :
- [ ] Feed abuse.ch parsé correctement (format CSV avec colonnes hash,description)
- [ ] Cache disque rechargé au démarrage si < 24h
- [ ] `LookupWithFeed` thread-safe, pas de lock sous scoring hot-path
- [ ] Test : feed avec hash connu → détection ; feed vide → fallback built-in

---

## Phase 2.4 — Multi-Interface Capture

### Pourquoi c'est élevé (opérationnel)

Un réseau réel a :
- `eth0` : trafic WAN
- `eth1` : trafic LAN interne
- `docker0`, `virbr0` : trafic container/VM
- Bond0, bridge0 : LAG/bonding

Aujourd'hui, le daemon capture sur UNE interface. Sur un hyperviseur avec plusieurs NIC,
on rate tout le trafic latéral inter-VM.

### Solution technique

L'aggregateur utilise déjà `sync.Map` — il est **nativement thread-safe pour writes concurrents**.
Il suffit de spawner un goroutine de capture par interface.

**Config : `DaemonConfig` modifié**

```go
type DaemonConfig struct {
    // Interfaces remplace Interface (backward compat : Interface peuplé → ajouté à Interfaces)
    Interface          string   `yaml:"interface"`   // kept for backward compat
    Interfaces         []string `yaml:"interfaces"`  // NEW: list of interfaces
    BPFFilter          string   `yaml:"bpf_filter"`
    CaptureIntervalSec int      `yaml:"capture_interval_seconds"`
}
```

**`daemon.go` — `runWindow()` modifié** :

```go
func runWindow(ctx context.Context, interfaces []string, bpfFilter string, dur time.Duration) error {
    winCtx, cancel := context.WithTimeout(ctx, dur)
    defer cancel()

    agg := &aggregate.Aggregator{}

    // Refresh socket table
    var tablePtr atomic.Pointer[correlate.SocketTable]
    tablePtr.Store(correlate.BuildSocketTable())
    go refreshSocketTable(winCtx, &tablePtr)

    // One capture goroutine per interface
    var wg sync.WaitGroup
    for _, iface := range interfaces {
        wg.Add(1)
        go func(iface string) {
            defer wg.Done()
            pktCh, err := capture.CapturePackets(winCtx, iface, bpfFilter)
            if err != nil {
                log.Printf("capture %s: %v", iface, err)
                return
            }
            for pkt := range pktCh {
                snap := tablePtr.Load()
                agPkt := translatePacketEvent(pkt, snap)
                agg.Add(agPkt) // sync.Map safe for concurrent goroutines
            }
        }(iface)
    }
    wg.Wait()

    // Finalize and persist as before
    flows := agg.Finalize(makeResolver(&tablePtr))
    ...
}
```

**`FlowRecord` — ajouter attribution d'interface** :
```go
Interface string `json:"interface,omitempty"` // e.g. "eth0", "eth1"
```

**`FlowKey` — NE PAS ajouter Interface** (on veut dédupliquer les flows entre interfaces — un même flow vu sur bond0 et eth0 doit être agrégé en un seul).

**Config YAML example** :
```yaml
daemon:
  interfaces:
    - "eth0"
    - "eth1"
    - "docker0"
  bpf_filter: "not port 22"
  capture_interval_seconds: 300
```

**Backward compat** : si `interfaces` vide et `interface` non vide → `interfaces = [interface]`.

**Critères de complétion** :
- [ ] `go test -race ./internal/daemon/...` vert (daemon coverage remonte de 14% → 60%+)
- [ ] Test : 2 goroutines injectant dans le même Aggregator simultanément → pas de race
- [ ] `get_daemon_stats` retourne `interfaces []string` dans la réponse MCP
- [ ] Config backward-compatible : `interface: "eth0"` (ancienne syntaxe) fonctionne encore

---

## Phase 2.5 — TLS Certificate Analysis

### Pourquoi c'est élevé

Les outils de pentest modernes (Metasploit, Sliver, Cobalt Strike) génèrent des certificats
auto-signés avec des caractéristiques détectables :
- Lifetime > 10 ans (openssl default)
- Subject CN = IP address ou nom générique (e.g. "localhost", "example.com")
- Pas de SAN (Subject Alternative Name)
- Issuer == Subject (auto-signé)
- Clé RSA 2048 exactement (tous les frameworks C2 par défaut)

### Solution technique

Le ServerCertificate TLS (handshake type 0x0B) est envoyé par le serveur **en clair** avant
l'établissement de la session chiffrée. Il contient le certificat DER encodé.

**Nouveau fichier : `internal/capture/tls_cert.go`**

```go
package capture

import (
    "crypto/x509"
    "time"
)

type CertInfo struct {
    IsSelfSigned  bool
    IsExpired     bool
    ValidityDays  int      // cert lifetime in days (> 365 suspicious post-2023)
    SubjectCN     string
    IssuerCN      string
    NotBefore     time.Time
    NotAfter      time.Time
    HasSAN        bool
    IsIPAddressCN bool     // CN is an IP address (unusual for legitimate certs)
}

// extractServerCert parses a TLS ServerCertificate message from raw TCP payload.
// Returns nil if the payload is not a TLS Certificate message.
func extractServerCert(payload []byte) *CertInfo {
    // TLS record type 0x16 (Handshake), handshake type 0x0B (Certificate)
    // Parse DER cert from first certificate in the chain
    // Use crypto/x509.ParseCertificate()
    ...
}
```

**Ajout au `PacketEvent`** :
```go
CertInfo *CertInfo // non-nil if TLS server certificate was parsed
```

**Scoring dans `aggregate.go`** :
```go
// ── TLS certificate anomalies ─────────────────────────────────────────────
if !cfg.DisableCertScoring && rec.CertInfo != nil {
    c := rec.CertInfo
    if c.IsSelfSigned {
        add(2.0, fmt.Sprintf("self-signed TLS certificate (CN=%s)", c.SubjectCN))
    }
    if c.IsExpired {
        add(1.5, "expired TLS certificate")
    }
    if c.ValidityDays > 3650 { // > 10 years
        add(1.5, fmt.Sprintf("suspicious cert lifetime: %d days", c.ValidityDays))
    }
    if c.IsIPAddressCN {
        add(1.0, fmt.Sprintf("TLS cert CN is IP address: %s", c.SubjectCN))
    }
    if !c.HasSAN && !c.IsSelfSigned {
        add(0.5, "TLS cert has no Subject Alternative Name (SAN)")
    }
}
```

**Note** : Nécessite `crypto/x509` (stdlib Go — aucune dépendance externe).

**Critères de complétion** :
- [ ] Parse correct des certs Cobalt Strike / Metasploit par défaut (tests avec certs synthétiques)
- [ ] Pas de panic sur cert malformé ou tronqué
- [ ] `go test -race ./internal/capture/...` vert
- [ ] Faux positif minimal : certs Let's Encrypt, DigiCert, etc. ne déclenchent pas

---

## Phase 2.6 — Prometheus Metrics Export

### Pourquoi utile

En daemon mode, aucune visibilité externe sur l'état de l'outil sans appeler `get_daemon_stats`.
Prometheus + Grafana permettent : alerting infra, dashboards NOC, intégration avec alertmanager.

### Solution technique

**Nouveau fichier : `internal/metrics/metrics.go`**

```go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "net/http"
)

var (
    FlowsScored = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "flowsentinel_flows_scored_total"},
        []string{"risk_level"},
    )
    AlertsFired = prometheus.NewCounter(
        prometheus.CounterOpts{Name: "flowsentinel_alerts_fired_total"},
    )
    DroppedPackets = prometheus.NewGauge(
        prometheus.GaugeOpts{Name: "flowsentinel_dropped_packets_total"},
    )
    WebhookFailures = prometheus.NewCounter(
        prometheus.CounterOpts{Name: "flowsentinel_webhook_failures_total"},
    )
    WindowDuration = prometheus.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "flowsentinel_capture_window_duration_seconds",
            Buckets: []float64{1, 5, 15, 30, 60, 120, 300},
        },
    )
)

// Serve starts the metrics HTTP server on :9200/metrics (configurable).
func Serve(addr string) error {
    prometheus.MustRegister(FlowsScored, AlertsFired, DroppedPackets,
                            WebhookFailures, WindowDuration)
    http.Handle("/metrics", promhttp.Handler())
    return http.ListenAndServe(addr, nil)
}
```

**Config addition** :
```yaml
metrics:
  enabled: false          # disabled by default (no external exposure)
  listen_addr: ":9200"    # Prometheus scrape endpoint
```

**Dépendance** : `github.com/prometheus/client_golang` (~5 MB, stable, widely used).

**Critères de complétion** :
- [ ] `curl http://localhost:9200/metrics` retourne les métriques en format Prometheus text
- [ ] Métriques incrémentées correctement dans daemon loop
- [ ] `metrics.enabled: false` (défaut) → aucun port ouvert, aucune dépendance réseau

---

## Phase 2.7 — HTTP/2 & gRPC Detection

### Pourquoi c'est moyen-élevé

Sliver C2 utilise gRPC (HTTP/2 + Protobuf) sur port 443 depuis v1.5.
C2 frameworks modernes migrent vers HTTP/2 précisément car il est difficile à inspecter.

Caractéristiques détectables sans déchiffrement :
- **Preface HTTP/2** : `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` (24 bytes, identique même après Sliver custom profiles)
- **SETTINGS frame** : type 0x04 immédiatement après preface
- **Header frame count élevé** sur port non-443 (HTTP/2 cleartext sur port 8080 → suspect)

### Solution technique

**Dans `capture/http.go`** (extension) :

```go
const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// isHTTP2Preface returns true if the payload starts with the HTTP/2 client preface.
func isHTTP2Preface(payload []byte) bool {
    return len(payload) >= 24 && string(payload[:24]) == http2ClientPreface
}

// isGRPCFrames tries to detect gRPC 5-byte frame header pattern:
// [compressed_flag(1)] [length(4)] [data...]
// Multiple consecutive valid frames = strong gRPC indicator
func isGRPCPattern(payload []byte) bool {
    if len(payload) < 5 { return false }
    pos := 0
    frames := 0
    for pos+5 <= len(payload) && frames < 3 {
        compFlag := payload[pos]
        if compFlag > 1 { return false } // compressed flag must be 0 or 1
        msgLen := int(binary.BigEndian.Uint32(payload[pos+1:]))
        if msgLen > 16*1024*1024 { return false } // > 16 MB = not gRPC
        pos += 5 + msgLen
        frames++
    }
    return frames >= 2 // 2+ valid frames = gRPC with high confidence
}
```

**Scoring** :
```go
if rec.IsHTTP2 && !standardHTTPSPorts[key.DstPort] {
    add(1.5, fmt.Sprintf("HTTP/2 on non-standard port %d — potential C2", key.DstPort))
}
if rec.IsGRPC {
    add(0.5, "gRPC traffic detected") // informational, needs context
}
```

**Critères de complétion** :
- [ ] Preface HTTP/2 détectée sur pcap Sliver réel
- [ ] Faux positif nul sur trafic gRPC Google (OK via SNI context)
- [ ] `go test -race ./internal/capture/...` vert

---

## Phase 2.8 — History Compression + Schema Versioning

### Problème

Le fichier JSONL actuel :
- Aucune compression : 1000 flows/session × 24h × 300 sessions = ~500 MB non compressé
- Aucun versioning : ajout de champ dans `FlowRecord` → anciens enregistrements incompatibles
- Aucune intégrité : corruption silencieuse (scan() skip les lignes malformées)

### Solution

```go
// Entry header avec version schema
type Entry struct {
    SchemaVersion int                    `json:"v"`        // NEW: 1 = current
    Timestamp     time.Time              `json:"timestamp"`
    Source        string                 `json:"source"`
    FlowCount     int                    `json:"flow_count"`
    Flows         []aggregate.FlowRecord `json:"flows"`
}

// Rotation journalière avec compression gzip
// ~/.cache/mcp-flowsentinel/history_2026-04-18.jsonl.gz
// ~/.cache/mcp-flowsentinel/history_current.jsonl (today, uncompressed)
```

**Config addition** :
```yaml
history:
  compress_rotated: true   # gzip les fichiers journaliers
  max_rotated_days: 7      # garder 7 jours compressés
```

**Critères de complétion** :
- [ ] Anciens enregistrements (v=0 implicite) lus sans erreur (backward compat)
- [ ] Fichiers .jsonl.gz lisibles par `zcat | jq`
- [ ] `go test -race ./internal/history/...` vert

---

## Phase 2.9 — Alerting Rate-Limit + HMAC Signing

### Problèmes

1. **Pas de rate-limit** : 1000 flows critical → 1000 POSTs webhook en rafale → DoS de l'endpoint
2. **Pas de signing** : endpoint ne peut pas vérifier que l'alerte vient de MCP-FlowSentinel

### Solution

```go
// Rate limiting : token bucket dans alerting.go
type rateLimiter struct {
    mu       sync.Mutex
    tokens   int
    maxBurst int
    refillAt time.Time
}
// Default: max 10 alerts/minute, burst 20

// HMAC signing : sha256(secret, payload)
// Config: alerting.webhook_secret (optionnel)
// Header: X-FlowSentinel-Signature: sha256=<hex>
```

**Config addition** :
```yaml
alerting:
  max_alerts_per_minute: 10  # rate limit
  webhook_secret: ""          # HMAC secret (empty = no signing)
```

**Critères de complétion** :
- [ ] `max_alerts_per_minute: 2` → 100 flows critical → 2 webhooks/min max
- [ ] Signature vérifiable avec standard HMAC-SHA256
- [ ] `go test -race ./internal/alerting/...` remonte de 70% → 85%+

---

## Phase 2.10 — IPv6 Extension Headers

### Problème

IPv6 extension headers (Routing Header type 0, Fragment Header, Hop-by-Hop) peuvent :
- Masquer le vrai transport layer (TLS, DNS) derrière des headers d'extension
- Être utilisés pour bypass de règles BPF naïves
- Fragmenter un ClientHello TLS sur plusieurs fragments IPv6

### Solution

```go
// Dans parsePacket(), après détection du network layer IPv6 :
// Itérer les extension headers jusqu'au transport layer réel
// Détecter IPv6 Routing Header type 0 (deprecated, RCE vector historique)
// Détecter fragments IPv6 (next_header == 44)
if ipv6RH0Detected {
    event.Flags |= FlagIPv6RoutingHeader0 // +1.5 pts scoring
}
if ipv6Fragmented {
    event.Flags |= FlagIPv6Fragmented     // informational
}
```

---

## Ordre d'implémentation recommandé

```
Semaine 1 : Phase 2.3 (JA3 feed, 1 jour) + Phase 2.4 (multi-interface, 1.5 jours)
            + Phase 2.6 (Prometheus, 0.5 jour) + Phase 2.9 (rate-limit, 0.5 jour)
            → 4 jours, impact opérationnel immédiat, complexité faible-moyenne

Semaine 2 : Phase 2.2 (HTTP parsing, 2 jours) + Phase 2.5 (TLS certs, 2 jours)
            → 4 jours, nouvelles surfaces de détection majeures

Semaine 3 : Phase 2.1 (TCP reassembly, 3 jours)
            → 3 jours, complexité la plus élevée, gain marginal en pratique
              (ClientHello fragmenté = < 0.1% du trafic réel)

Semaine 4 : Phase 2.7 (HTTP/2 gRPC, 2 jours) + Phase 2.8 (history, 1 jour)
            + Phase 2.10 (IPv6, 1 jour)
            → 4 jours, polish production
```

---

## Ce que cela donnera après implémentation complète

| Capacité | Avant (actuel) | Après (Phase 2 complète) |
|----------|---------------|--------------------------|
| Cobalt Strike HTTP default | ❌ invisible | ✅ User-Agent + URI entropy |
| Cobalt Strike HTTPS default | ✅ JA3 hash | ✅ JA3 + cert auto-signé + cert lifetime |
| Sliver gRPC/HTTP2 | ❌ invisible | ✅ HTTP/2 preface + gRPC pattern + port anomaly |
| ClientHello fragmenté | ❌ JA3 manqué | ✅ TCP reassembly |
| C2 sur JA3 non-documenté | ❌ invisible | ✅ Dynamic feed abuse.ch + JA3S |
| Multi-NIC / hyperviseur | ❌ une interface | ✅ N interfaces en parallèle |
| Métriques NOC | ❌ | ✅ Prometheus /metrics |
| Certification des alertes | ❌ | ✅ HMAC-SHA256 |

### Position compétitive résultante

MCP-FlowSentinel Phase 2 sera le **seul outil open-source qui combine** :
1. Visibilité réseau L3-L7 (TLS/DNS/HTTP/HTTP2/QUIC)
2. Corrélation process/socket native (aucun autre outil réseau ne fait ça)
3. Interface LLM native (MCP) pour interrogation en langage naturel
4. Scoring de menaces enrichi MITRE ATT&CK
5. Zero infra required (single binary, no Elastic, no rules DB)

**Zeek reste supérieur** sur : throughput (40 Gb/s vs ~1 Gb/s), couverture protocoles (30+ vs 6), déploiement distribué, règles communautaires (50K+ Zeek scripts).

**MCP-FlowSentinel sera supérieur** sur : corrélation process, expérience LLM, déploiement (single binary), analyse forensique pcap interactive, accessibilité (pas de formation Zeek scripting requise).
