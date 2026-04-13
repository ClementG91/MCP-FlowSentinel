# MCP-FlowSentinel — Plan d'Implémentation Expert

> **Objectif :** Surpasser Zeek, Suricata et les outils EDR dans le contexte AI-first.  
> **Zéro bug connu à la fin de chaque phase.**  
> **Chaque tâche inclut : fichiers, approche exacte, critères d'acceptation testables.**

---

## Graphe de dépendances

```
Phase 0 (Bugs critiques)
  ├─► Phase 1 (Moteur de détection)
  │     ├─► Phase 2 (UX / Config)
  │     └─► Phase 3 (Nouveaux outils MCP)
  └─► Phase 4 (Performance)       ← parallélisable avec Phase 2/3
Phase 0 + 1 + 2 + 3 ─► Phase 5 (Polish, README, Release)
```

**Bloquants durs :**
- Bug #5 (YAML zero-value) et #9 (panic dns_workers) → avant tout travail de config
- Bug #1 (dedupMap growth) → avant `suppress_alert` (Phase 3)
- Bug #3 (packet drop silencieux) → avant détection QUIC / beaconing amélioré

---

## Estimation globale

| Phase | Contenu | Jours-homme |
|-------|---------|-------------|
| 0 | Bugs critiques | 5–6 j |
| 1 | Moteur de détection | 14–18 j |
| 2 | UX / Config / Observabilité | 6–8 j |
| 3 | Nouveaux outils MCP | 5–6 j |
| 4 | Performance & scalabilité | 5–7 j |
| 5 | Polish, README, Release | 3–4 j |
| **Total** | | **38–49 j** |

---

---

# Phase 0 — Bugs Critiques (blocker)

> **Règle :** chaque fix livré avec un test qui reproduit le bug avant correction.

---

## 0.1 — `dedupMap` grandit sans limite

**Fichier :** `internal/alerting/alerting.go`

**Problème :** `dedupMap map[string]time.Time` accumule toutes les clés pour toujours. Après 1 mois = millions d'entrées, lookups O(n).

**Approche :**
```go
// Remplacer la map simple par un nettoyage périodique
// Lancer une goroutine de cleanup dans init() ou dans Fire() au premier appel
func evictExpiredDedupEntries(windowSec int) {
    dedupMu.Lock()
    defer dedupMu.Unlock()
    cutoff := time.Now().Add(-time.Duration(windowSec) * time.Second)
    for k, t := range dedupMap {
        if t.Before(cutoff) {
            delete(dedupMap, k)
        }
    }
}
// Appel : go func() { ticker := time.NewTicker(5*time.Minute); for range ticker.C { evictExpiredDedupEntries(cfg.Alerting.DeduplicationWindowSec) } }()
```

**Critères d'acceptation :**
- [ ] Test : injecter 1000 clés avec TTL expiré → après eviction, `len(dedupMap) == 0`
- [ ] Test : clés non-expirées survivent à l'eviction
- [ ] Aucune data race sous `-race`

---

## 0.2 — Regex invalide silencieusement ignorée

**Fichier :** `internal/config/config.go:265`

**Problème :** `compileScoringPatterns` ignore les erreurs de compilation. L'utilisateur pense que sa règle est active.

**Approche :**
```go
// Dans Load(), après yaml.Unmarshal :
func validateAndCompileScoringPatterns(cfg *Config) error {
    cfg.Scoring.CompiledExtraCmdlinePatterns = nil
    for _, pat := range cfg.Scoring.ExtraCmdlinePatterns {
        re, err := regexp.Compile(pat)
        if err != nil {
            return fmt.Errorf("extra_cmdline_patterns: invalid regex %q: %w", pat, err)
        }
        cfg.Scoring.CompiledExtraCmdlinePatterns = append(cfg.Scoring.CompiledExtraCmdlinePatterns, re)
    }
    return nil
}
```

**Critères d'acceptation :**
- [ ] `Load()` retourne une erreur explicite sur regex invalide
- [ ] Regex valides compilées normalement
- [ ] Test table-driven : 3 cas invalides, 2 cas valides

---

## 0.3 — Packet channel drop silencieux

**Fichier :** `internal/capture/capture.go:48`

**Problème :** `ch := make(chan PacketEvent, 4096)` — si l'agrégateur est lent, les paquets sont droppés sans log.

**Approche :**
```go
var droppedPackets atomic.Int64

// DroppedPackets retourne le total de paquets droppés depuis le démarrage.
func DroppedPackets() int64 { return droppedPackets.Load() }

// Dans la goroutine de lecture :
select {
case ch <- event:
default:
    droppedPackets.Add(1)
    if droppedPackets.Load()%1000 == 1 {
        log.Printf("capture: WARNING — packet channel full, %d packets dropped total", droppedPackets.Load())
    }
}
```

Exposer `DroppedPackets()` dans `daemon.GetStats()`.

**Critères d'acceptation :**
- [ ] `DroppedPackets()` s'incrémente quand le channel est plein
- [ ] Log de warning affiché tous les 1000 drops
- [ ] Visible dans `get_daemon_stats`

---

## 0.4 — IPv6 link-local non exemptée

**Fichier :** `internal/aggregate/aggregate.go` (fonction `isPrivateIP`)

**Problème :** `fe80::/10` (link-local), `fc00::/7` (ULA), `::1` (loopback) non inclus → pénalité PTR +0.8 sur toutes les adresses IPv6 locales normales.

**Approche :**
```go
func isPrivateIP(ip string) bool {
    parsed := net.ParseIP(ip)
    if parsed == nil {
        return false
    }
    // IPv4 private ranges
    privateIPv4 := []string{"10.0.0.0/8","172.16.0.0/12","192.168.0.0/16",
        "127.0.0.0/8","169.254.0.0/16","0.0.0.0/8"}
    // IPv6 private ranges
    privateIPv6 := []string{"::1/128","fc00::/7","fe80::/10","::ffff:0:0/96","100::/64"}
    all := append(privateIPv4, privateIPv6...)
    for _, cidr := range all {
        _, network, _ := net.ParseCIDR(cidr)
        if network != nil && network.Contains(parsed) {
            return true
        }
    }
    return false
}
```

Pré-compiler les CIDRs au `init()` pour éviter le parsing à chaque appel.

**Critères d'acceptation :**
- [ ] `fe80::1`, `fc00::1`, `::1`, `fd00::1` → `isPrivateIP() == true`
- [ ] `2001:db8::1` (global) → `isPrivateIP() == false`
- [ ] Test unitaire couvrant tous les ranges

---

## 0.5 — YAML zero-value écrase les defaults

**Fichier :** `internal/config/config.go:218-256`

**Problème :** `yaml.Unmarshal(data, cfg)` où `cfg = Default()`. Si l'utilisateur écrit `capture:` sans sous-champs, tous les entiers passent à 0.

**Approche :** Unmarshaler en deux étapes avec merge explicite :
```go
// 1. Parser dans une struct intermédiaire avec tous les champs pointeurs
type rawConfig struct {
    Scoring  *ScoringConfig  `yaml:"scoring"`
    Capture  *CaptureConfig  `yaml:"capture"`
    // ...
}
// 2. Ne merger que les sections présentes dans le YAML
var raw rawConfig
if err := yaml.Unmarshal(data, &raw); err != nil { ... }
if raw.Capture != nil {
    if raw.Capture.DefaultDurationSec > 0 { cfg.Capture.DefaultDurationSec = raw.Capture.DefaultDurationSec }
    // ...
}
```

Ou utiliser la bibliothèque `github.com/imdario/mergo` pour merge non-zero.

**Critères d'acceptation :**
- [ ] YAML avec `capture:` vide → defaults conservés
- [ ] YAML avec `capture:\n  default_duration_seconds: 10` → seulement ce champ changé
- [ ] Test : chaque section peut être omise sans casser les defaults

---

## 0.6 — Score peut dépasser 10.0

**Fichier :** `internal/aggregate/aggregate.go` (logique scoring)

**Problème :** Le scoring en deux passes peut empiler des bonus sans vérification intermédiaire.

**Approche :** Centraliser tout le scoring dans une fonction `scoreFlow(f *FlowRecord) float64` qui retourne `math.Min(score, 10.0)`. Jamais d'assignation directe à `SuspicionScore` hors de cette fonction.

**Critères d'acceptation :**
- [ ] Test : flow avec tous les signaux actifs → score == 10.0, pas 11.5
- [ ] `SuspicionScore` jamais > 10.0 dans aucun test

---

## 0.7 — Beaconing fire sur SSH keepalives

**Fichier :** `internal/aggregate/aggregate.go` (calcul beaconing)

**Problème :** SSH keepalives toutes les 30s avec CV=0.02 = CRITICAL beaconing. Aucun seuil d'intervalle minimum.

**Approche :**
```go
// Ajouter dans ScoringConfig :
BeaconingMinIntervalSec float64 `yaml:"beaconing_min_interval_seconds"` // default: 5.0

// Dans le calcul beaconing — si l'intervalle médian < MinIntervalSec, skip
medianInterval := computeMedianInterval(timestamps)
if medianInterval < cfg.Scoring.BeaconingMinIntervalSec {
    continue // trop rapide pour être du C2, probable traffic réseau normal
}
```

Default `beaconing_min_interval_seconds: 5.0` — en dessous de 5s d'intervalle, pas de scoring beaconing.

**Critères d'acceptation :**
- [ ] SSH keepalives à 30s → toujours scorées (> 5s)
- [ ] Paquets TCP à 100ms → pas de scoring beaconing
- [ ] Test unitaire avec timestamps synthétiques

---

## 0.8 — Webhook failure silencieuse

**Fichier :** `internal/alerting/alerting.go`, `internal/daemon/daemon.go`

**Problème :** Erreur POST webhook = log stderr seulement. Zéro visibilité dans les stats.

**Approche :**
```go
var webhookFailures atomic.Int64

// Dans post() :
if err != nil {
    webhookFailures.Add(1)
    log.Printf("alerting: webhook POST failed (%d total failures): %v", webhookFailures.Load(), err)
    return
}

func WebhookFailures() int64 { return webhookFailures.Load() }
```

Exposer dans `daemon.GetStats()` : `WebhookFailures int64 \`json:"webhook_failures"\``

**Critères d'acceptation :**
- [ ] `WebhookFailures()` s'incrémente sur erreur réseau
- [ ] Visible dans `get_daemon_stats`
- [ ] Retry avec backoff exponentiel (3 tentatives max, 1s/2s/4s)

---

## 0.9 — Panic sur `dns_workers: 0`

**Fichier :** `internal/config/config.go:validate()`

**Problème :** La validation existe mais incomplète. `dns_workers: 0` passe la validation et provoque un panic dans le worker pool.

**Approche :** Étendre `validate()` :
```go
if c.DNSWorkers < 1 || c.DNSWorkers > 200 {
    return fmt.Errorf("capture.dns_workers must be in [1, 200], got %d", c.DNSWorkers)
}
if c.DNSCacheTTLSec < 0 {
    return fmt.Errorf("capture.dns_cache_ttl_seconds must be >= 0, got %d", c.DNSCacheTTLSec)
}
if cfg.Alerting.DeduplicationWindowSec < 0 {
    return fmt.Errorf("alerting.deduplication_window_seconds must be >= 0")
}
```

**Critères d'acceptation :**
- [ ] `dns_workers: 0` → erreur explicite au chargement
- [ ] `dns_workers: 201` → erreur explicite
- [ ] Tests pour chaque nouveau cas de validation

---

## 0.10 — History full scan à chaque query

**Fichier :** `internal/history/history.go`

**Problème :** `Query()` scanne tout le fichier JSONL à chaque appel. Avec 50 MB et 100K entrées, chaque query AI charge tout en mémoire.

**Approche court terme (Phase 0) :** Limiter le scan aux N dernières lignes via lecture inversée (tail-from-end) avant parsing complet. Utiliser `bufio.Scanner` en mode inverse avec buffer.

**Approche long terme (Phase 4) :** Index en mémoire (voir Phase 4).

**Critères d'acceptation :**
- [ ] Query avec `max_age_hours: 1` ne charge pas les 23h restantes
- [ ] Benchmark : query sur fichier 50 MB < 200ms

---

---

# Phase 1 — Moteur de Détection

> **Objectif :** Dépasser Zeek sur les signaux réseau. Chaque signal : scoring calibré, kill-switch, test unitaire.

---

## 1.1 — Analyse protocole HTTP (layer 7)

**Nouveaux fichiers :**
- `internal/capture/http.go` — parser HTTP/1.1 dans les payloads TCP
- `internal/aggregate/http_scoring.go` — signaux de scoring HTTP

**Signaux à implémenter :**

| Signal | Score | Rationale |
|--------|-------|-----------|
| Méthode `CONNECT` vers IP non-proxy | +2.0 | HTTP tunneling |
| User-Agent vide ou générique (`Go-http-client`, `python-requests`) | +1.0 | C2 frameworks paresseux |
| User-Agent avec version Windows ancienne (`MSIE 6.0`) | +1.5 | Malware qui spoofs |
| Storm de 404 (≥ 10 en 60s vers même host) | +2.5 | Scanning de ressources |
| Storm de 401 (≥ 5 en 60s) | +2.0 | Brute force auth |
| Redirect chain ≥ 4 (302→302→...) | +1.0 | Phishing / evasion |
| `Content-Type: application/octet-stream` sur port 80/8080 | +1.5 | Exfiltration déguisée |

**Approche parsing :**
```go
// Dans capture.go, après assemblage TCP stream (flows établis) :
// Utiliser net/http pour parser les premiers 4KB du payload
if isHTTPPayload(payload) {
    req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
    if err == nil {
        event.HTTPMethod = req.Method
        event.HTTPUserAgent = req.Header.Get("User-Agent")
        event.HTTPHost = req.Host
    }
}
```

Ajouter dans `FlowRecord` :
```go
HTTPMethod    string `json:"http_method,omitempty"`
HTTPUserAgent string `json:"http_user_agent,omitempty"`
HTTPHost      string `json:"http_host,omitempty"`
HTTPStatusCodes []int `json:"http_status_codes,omitempty"`
```

**Kill-switch :** `disable_http_scoring: false`

**Critères d'acceptation :**
- [ ] Test : payload HTTP CONNECT → `HTTPMethod == "CONNECT"`
- [ ] Test : User-Agent vide → +1.0 pts
- [ ] Test : 10× 404 vers même host → +2.5 pts
- [ ] Aucun parsing sur UDP, QUIC, ou flows sans payload TCP

---

## 1.2 — TLS : inspection certificat + version + JA3S

**Fichiers :** `internal/capture/capture.go`, `internal/ja3/ja3.go`, `internal/aggregate/aggregate.go`

**Signaux :**

| Signal | Score | Rationale |
|--------|-------|-----------|
| TLS 1.0 ou 1.1 (version négociée) | +1.5 | Obsolète, downgrade attack |
| Certificat auto-signé (ServerHello sans CA chain) | +2.0 | C2 infrastructure typique |
| Certificat expiré | +1.5 | Malware lazy |
| CN/SAN = IP brute (pas de hostname) | +1.5 | Direct C2 IP |
| Certificat valide < 24h ou > 398 jours | +1.0 | Let's Encrypt abuse ou très vieux cert |
| **JA3S match known-bad** | +4.0 | Server fingerprint malware |
| JA3S inconnu + JA3 connu-bad | +1.0 | Confirmation |

**Approche JA3S :**
```go
// Dans la réponse TLS ServerHello, extraire :
// TLSVersion + CipherSuite choisi + Extensions du server
// JA3S = MD5(TLSVersion,CipherSuite,Extensions)
func ComputeJA3S(serverHello *tls.ServerHelloInfo) string {
    // ...
}
```

Ajouter dans `FlowRecord` :
```go
JA3SHash        string `json:"ja3s_hash,omitempty"`
JA3SKnownBad    string `json:"ja3s_known_bad,omitempty"`
TLSVersion      string `json:"tls_version,omitempty"`
TLSCertIssuer   string `json:"tls_cert_issuer,omitempty"`
TLSCertExpiry   string `json:"tls_cert_expiry,omitempty"`
TLSCertSelfSigned bool `json:"tls_cert_self_signed,omitempty"`
```

**Base JA3S known-bad :** Partir du dataset [salesforce/ja3](https://github.com/salesforce/ja3) server fingerprints.

**Critères d'acceptation :**
- [ ] TLS 1.0 capturé → TLSVersion == "TLS 1.0", +1.5 pts
- [ ] Certificat auto-signé → TLSCertSelfSigned == true, +2.0 pts
- [ ] JA3S known-bad → +4.0 pts
- [ ] Test avec pcap synthétique (openssl s_server avec cert self-signed)

---

## 1.3 — DNS : analyse réponse + détection anomalies

**Fichier :** `internal/capture/capture.go`, `internal/aggregate/dns_scoring.go`

**Signaux :**

| Signal | Score | Rationale |
|--------|-------|-----------|
| NXDOMAIN storm (≥ 10 NXDOMAIN en 60s) | +3.0 | DGA (Domain Generation Algorithm) |
| SERVFAIL répétés (≥ 5 en 60s) | +1.5 | Tentative de résolution malveillante |
| TTL anormalement bas (< 60s) | +1.0 | Fast-flux C2 infrastructure |
| TTL 0 | +2.0 | DNS exfiltration classique |
| Réponse DNS avec IP dans espace privé | +2.5 | DNS rebinding attack |
| Requête DNS vers IP non-53 (DNS over non-standard port) | +3.0 | Evasion de filtrage DNS |
| DNS-over-TLS (port 853) | +0.5 | DoT — peut bypasser surveillance |
| Query type TXT avec payload long (> 100 chars) | +2.0 | DNS exfiltration par TXT records |

**Ajouter dans `PacketEvent` :**
```go
DNSResponseCode  int      // 0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN
DNSTTL           uint32
DNSAnswerIPs     []string
DNSQueryType     uint16   // A=1, AAAA=28, TXT=16, MX=15
```

Utiliser `github.com/google/gopacket/layers` (déjà dépendance) pour parser les réponses DNS.

**Kill-switch :** `disable_dns_response_scoring: false`

**Critères d'acceptation :**
- [ ] 10× NXDOMAIN en 60s → +3.0 pts, reason "dns_nxdomain_storm"
- [ ] TTL=0 dans réponse → +2.0 pts
- [ ] DNS rebinding (réponse = 192.168.x.x pour nom public) → +2.5 pts
- [ ] Query TXT > 100 chars → +2.0 pts

---

## 1.4 — QUIC / HTTP3 détection

**Fichier :** `internal/capture/capture.go`, `internal/aggregate/quic_scoring.go`

**Problème :** QUIC est UDP 443. Le tool est actuellement aveugle dessus.

**Approche — pas de parsing QUIC complet (trop complexe), scoring heuristique :**
```go
// Détecter les paquets UDP 443 avec signature QUIC initiale
// QUIC Initial packet commence par 0xC0 (long header) + version
func isQUICInitial(payload []byte) bool {
    if len(payload) < 5 { return false }
    return payload[0]&0x80 != 0 && // long header
           (payload[1] == 0x00 && payload[2] == 0x00 && payload[3] == 0x00 && payload[4] == 0x01) // QUIC v1
}
```

**Signaux QUIC :**

| Signal | Score | Rationale |
|--------|-------|-----------|
| QUIC vers IP sans reverse DNS | +0.5 | Bypasse filtrage DNS |
| QUIC vers IP dans high-risk ASN | +1.0 | Infrastructure suspecte |
| QUIC depuis process non-browser | +1.5 | Seuls browsers utilisent QUIC légitimement |
| Volume élevé QUIC UDP (> 10 MB) | +0.5 | Possible exfiltration |

Ajouter `IsQUIC bool \`json:"is_quic,omitempty"\`` dans `FlowRecord`.

**Kill-switch :** `disable_quic_scoring: false`

**Critères d'acceptation :**
- [ ] Paquets UDP 443 avec header QUIC → `IsQUIC == true`
- [ ] Process non-browser + QUIC → +1.5 pts
- [ ] Chrome/Firefox QUIC → 0 pts additionnels

---

## 1.5 — Réputation IP via AbuseIPDB

**Nouveau fichier :** `internal/intel/abuseipdb.go`

**API :** [AbuseIPDB](https://www.abuseipdb.com/api) — tier gratuit : 1000 lookups/jour.

**Approche :**
```go
type AbuseIPDBResult struct {
    AbuseConfidenceScore int    `json:"abuseConfidenceScore"` // 0-100
    CountryCode          string `json:"countryCode"`
    ISP                  string `json:"isp"`
    TotalReports         int    `json:"totalReports"`
    LastReportedAt       string `json:"lastReportedAt"`
}

func LookupReputation(ip string) (*AbuseIPDBResult, error) {
    // HTTP GET avec clé API depuis config ou env ABUSEIPDB_API_KEY
    // Cache LRU (1000 entrées, TTL 1h) pour ne pas épuiser le quota
}
```

**Scoring :**

| Confidence Score | Score | Rationale |
|-----------------|-------|-----------|
| 80–100 | +3.5 | IP très probablement malveillante |
| 50–79 | +2.0 | IP signalée comme suspecte |
| 20–49 | +1.0 | IP avec signalements mineurs |

**Config :**
```yaml
intel:
  abuseipdb_api_key: ""  # ou env ABUSEIPDB_API_KEY
  abuseipdb_enabled: false  # off par défaut (nécessite clé)
  abuseipdb_min_confidence: 20  # ne pas scorer en dessous
  abuseipdb_cache_ttl_minutes: 60
```

Ajouter dans `FlowRecord` :
```go
AbuseIPDBScore    int    `json:"abuseipdb_score,omitempty"`
AbuseIPDBReports  int    `json:"abuseipdb_reports,omitempty"`
```

**Critères d'acceptation :**
- [ ] IP connue malveillante (ex: 89.248.167.131) → score >= 80 → +3.5 pts
- [ ] Cache évite double lookup sur même IP dans la même session
- [ ] Quota épuisé → graceful degradation (log warning, pas d'erreur)
- [ ] Aucun lookup sur IPs privées

---

## 1.6 — Détection mouvement latéral (RFC1918 → RFC1918)

**Fichier :** `internal/aggregate/lateral_scoring.go`

**Signaux :**

| Signal | Score | Rationale |
|--------|-------|-----------|
| Connexion vers port 445 (SMB) depuis host non-DC | +2.0 | Lateral movement classique |
| Connexion vers port 3389 (RDP) depuis host inhabituel | +2.0 | Remote access suspect |
| Connexion vers port 22 (SSH) depuis process non-terminal | +1.5 | Automated SSH lateral |
| Scan de ports en RFC1918 (≥ 8 IPs internes uniques) | +2.5 | Internal scan |
| WMI (port 135 + 49152+) depuis workstation | +2.0 | WMI execution lateral |
| LDAP (port 389/636) depuis process non-AD | +1.5 | AD enumeration |

**Ajouter dans `ScoringConfig` :**
```yaml
# Ports critiques internes (par défaut : SMB, RDP, SSH, WMI, LDAP)
internal_sensitive_ports: [22, 135, 389, 445, 636, 3389]
disable_lateral_movement_scoring: false
```

**Critères d'acceptation :**
- [ ] `192.168.1.10:50000 → 192.168.1.20:445` → +2.0 pts
- [ ] Scan interne ≥ 8 IPs RFC1918 → +2.5 pts
- [ ] Connexion légitime d'un DC → non scorée si process == "lsass.exe" + exemptée

---

## 1.7 — Détection anomalies de protocole

**Fichier :** `internal/aggregate/protocol_anomaly.go`

**Signaux :**

| Signal | Score | Rationale |
|--------|-------|-----------|
| DNS sur port non-53 (ex: TCP 5353 sans mDNS) | +3.0 | DNS tunneling |
| HTTP sur port non-80/8080/443/8443 | +1.5 | C2 sur port inhabituel |
| SSH sur port non-22 | +0.5 | Evasion de règles firewall |
| SMTP sur port non-25/465/587 | +2.0 | Spam relay / exfil email |
| FTP sur port non-20/21 | +1.5 | Exfiltration données |
| Payload non-TLS sur port 443 | +2.0 | Tunnel déguisé |

**Approche :** Heuristique sur les premiers octets du payload pour identifier le protocole, puis vérifier la cohérence avec le port.

**Critères d'acceptation :**
- [ ] TCP payload avec header DNS sur port 8888 → +3.0 pts
- [ ] HTTP GET sur port 4444 → +1.5 pts (en plus du scoring bad-port)
- [ ] mDNS légitime (UDP 5353 multicast) → exempté

---

## 1.8 — MITRE ATT&CK tagging

**Nouveau fichier :** `internal/intel/mitre.go`

**Approche :** Table de correspondance `signal → technique_id`:

```go
var mitreMapping = map[string]MITRETechnique{
    "beaconing_strong":        {ID: "T1071.001", Name: "Application Layer Protocol: Web Protocols"},
    "dns_exfiltration":        {ID: "T1048.003", Name: "Exfiltration Over DNS"},
    "ja3_known_bad":           {ID: "T1071.001", Name: "Application Layer Protocol"},
    "port_scan_internal":      {ID: "T1046", Name: "Network Service Discovery"},
    "lateral_smb":             {ID: "T1021.002", Name: "Remote Services: SMB/Windows Admin Shares"},
    "lateral_rdp":             {ID: "T1021.001", Name: "Remote Services: Remote Desktop Protocol"},
    "http_connect_tunnel":     {ID: "T1572", Name: "Protocol Tunneling"},
    "dns_nxdomain_storm":      {ID: "T1568.002", Name: "Dynamic Resolution: Domain Generation Algorithms"},
    "tls_self_signed":         {ID: "T1573.001", Name: "Encrypted Channel: Symmetric Cryptography"},
    "high_rate_transfer":      {ID: "T1041", Name: "Exfiltration Over C2 Channel"},
    "missing_sni":             {ID: "T1071.001", Name: "Application Layer Protocol"},
    "geo_high_risk":           {ID: "T1090.003", Name: "Proxy: Multi-hop Proxy"},
    "abuseipdb_high":          {ID: "T1583", Name: "Acquire Infrastructure"},
}
```

Ajouter dans `FlowRecord` :
```go
MITRETechniques []MITRETechnique `json:"mitre_techniques,omitempty"`
```

**Critères d'acceptation :**
- [ ] Flow avec `beaconing_strong` → `mitre_techniques` contient T1071.001
- [ ] Flow avec plusieurs signaux → plusieurs techniques distinctes (dédupliquées)
- [ ] Test unitaire sur mapping complet

---

## 1.9 — Scoring directionnel (exfiltration)

**Fichier :** `internal/aggregate/aggregate.go`

**Problème :** `ByteCount` compte les bytes bidirectionnels. Exfil = sent >> received.

**Approche :**
```go
// Séparer les counters dans FlowAccumulator
BytesSent     int64
BytesReceived int64

// Scoring
ratio := float64(flow.BytesSent) / float64(max(flow.BytesReceived, 1))
if flow.BytesSent > 1*1024*1024 && ratio > 10.0 {
    score += 1.5 // exfiltration asymétrique
    reasons = append(reasons, fmt.Sprintf("asymmetric_upload ratio=%.1f", ratio))
}
```

Ajouter dans `FlowRecord` :
```go
BytesSent     int64 `json:"bytes_sent"`
BytesReceived int64 `json:"bytes_received"`
UploadRatio   float64 `json:"upload_ratio,omitempty"`
```

**Critères d'acceptation :**
- [ ] Flow 10 MB envoyé, 1 KB reçu → +1.5 pts, reason "asymmetric_upload"
- [ ] Flow équilibré → 0 pts additionnels
- [ ] Test avec packets synthétiques bidirectionnels

---

## 1.10 — Expansion base JA3 known-bad

**Fichier :** `internal/ja3/ja3.go`

**État actuel :** 15 hashes. Couverture très partielle.

**Approche :**
1. Intégrer le dataset complet [trisulnsm/ja3db](https://github.com/trisulnsm/ja3db) (400+ hashes documentés)
2. Intégrer [salesforce/ja3](https://github.com/salesforce/ja3) server fingerprints pour JA3S
3. Ajouter champ `Family` (Cobalt Strike, Meterpreter, etc.) et `Confidence` (high/medium/low)

```go
type JA3Entry struct {
    Hash        string
    Description string
    Family      string  // "Cobalt Strike", "Meterpreter", etc.
    Confidence  string  // "high", "medium", "low"
    Source      string  // "salesforce", "trisul", "custom"
}
```

**Script de génération :** `scripts/update_ja3_db.go` — télécharge les datasets et génère `ja3_db.go`.

**Critères d'acceptation :**
- [ ] Base ≥ 300 hashes JA3 client
- [ ] Base ≥ 50 hashes JA3S serveur
- [ ] Chaque hash a Family + Confidence
- [ ] `LookupWithCustom` retourne toutes les métadonnées

---

---

# Phase 2 — UX / Config / Observabilité

---

## 2.1 — Presets d'environnement

**Fichier :** `internal/config/config.go`, `internal/config/presets.go`

**Problème :** Un dev avec Flask sur 5000 voit des faux positifs constants. Un serveur bare-metal voit des manques.

**Approche :**
```go
// Nouveau champ Config
Environment string `yaml:"environment"` // "developer", "server", "enterprise", "container"

// Presets qui ajustent les defaults selon l'environnement
func ApplyEnvironmentPreset(cfg *Config, env string) {
    switch env {
    case "developer":
        cfg.Scoring.ExtraStandardPorts = append(cfg.Scoring.ExtraStandardPorts, 3000, 5000, 8000, 8080, 9000)
        cfg.Scoring.DisableBinaryPathScoring = true  // /tmp est normal en dev
        cfg.Alerting.MinScoreThreshold = 8.0         // plus strict pour réduire le bruit
    case "container":
        cfg.Scoring.DisableBinaryPathScoring = true
        cfg.Scoring.ExemptedProcesses = append(cfg.Scoring.ExemptedProcesses, "containerd", "dockerd", "kubelet")
    case "enterprise":
        cfg.Scoring.InternalSensitivePorts = []int{22, 135, 389, 445, 636, 3389, 5985, 5986}
        cfg.Alerting.MinScoreThreshold = 5.0  // plus sensible
    }
}
```

CLI : `mcp-flowsentinel --init-config --environment developer`

**Critères d'acceptation :**
- [ ] `--init-config --environment developer` → config avec ports dev inclus, /tmp exempté
- [ ] Test : preset "container" → `DisableBinaryPathScoring == true`
- [ ] README documente les 4 presets

---

## 2.2 — Exemptions par IP/CIDR

**Fichier :** `internal/config/config.go`, `internal/aggregate/aggregate.go`

**Problème :** Impossible d'exempter un proxy interne ou un endpoint de confiance.

**Approche :**
```go
// Dans ScoringConfig :
ExemptedCIDRs []string `yaml:"exempted_cidrs"`  // ["10.0.0.50/32", "172.16.0.0/12"]

// Pré-compiler dans config.go (comme ExtraCmdlinePatterns) :
CompiledExemptedCIDRs []*net.IPNet `yaml:"-"`

// Dans scoring :
func isExemptedCIDR(ip string, nets []*net.IPNet) bool {
    parsed := net.ParseIP(ip)
    for _, n := range nets {
        if n.Contains(parsed) { return true }
    }
    return false
}
```

**Critères d'acceptation :**
- [ ] Flow vers IP dans `exempted_cidrs` → score 0, reason "exempted_cidr"
- [ ] CIDRs invalides → erreur à `Load()`
- [ ] Test : exemption `/32`, exemption `/16`, non-match

---

## 2.3 — Commande `--explain-config`

**Fichier :** `main.go`

**Objectif :** Afficher la config active avec une explication humaine de chaque valeur.

```bash
$ mcp-flowsentinel --explain-config
Configuration active (chargée depuis ~/.config/mcp-flowsentinel/config.yaml)

SCORING:
  beaconing_strong_cv: 0.15
    → Détecte les connexions dont l'intervalle est très régulier (CV < 15%).
      Plus la valeur est basse, plus la détection est stricte.
      Augmenter si vous avez beaucoup de faux positifs sur les agents de monitoring.

  disable_binary_path_scoring: false
    → Actif — pénalise les binaires dans /tmp, /var/tmp, AppData\Local\Temp.
      Désactiver si vous travaillez en environnement container/CI.
  ...
```

**Critères d'acceptation :**
- [ ] Chaque champ de `ScoringConfig` + `AlertingConfig` expliqué
- [ ] Valeur active affichée
- [ ] Conseil contextuel (ex: si `disable_binary_path_scoring: false` et `/tmp` scoré récemment → suggère de l'activer)

---

## 2.4 — Outil MCP `explain_flow`

**Nouveau fichier :** `internal/tools/explain_flow.go`

**Objectif :** L'AI peut demander une explication détaillée d'un flow spécifique.

**Input :** `dedupe_key` (ex: `10.0.0.1:54321→1.2.3.4:443/TCP`)

**Output :**
```json
{
  "flow": { ... },
  "score_breakdown": [
    {"signal": "beaconing_strong", "points": 3.5, "detail": "CV=0.08 sur 47 paquets, intervalle médian=30.2s"},
    {"signal": "missing_sni", "points": 0.7, "detail": "TLS ClientHello sans extension SNI sur port 443"},
    {"signal": "geo_high_risk", "points": 1.5, "detail": "AS20473 (Vultr) — classé bulletproof hoster"}
  ],
  "mitre_techniques": ["T1071.001", "T1573.001"],
  "recommended_action": "Investiguer le processus chrome.exe — connexion régulière vers IP sans nom de domaine"
}
```

**Critères d'acceptation :**
- [ ] Breakdown score correspond exactement aux raisons dans `SuspicionReasons`
- [ ] `recommended_action` généré depuis template par risk level + signaux actifs
- [ ] Flow introuvable → erreur claire

---

## 2.5 — Outil MCP `suppress_alert`

**Nouveau fichier :** `internal/tools/suppress_alert.go`

**Objectif :** Whitelister un flow ou une IP pour les alertes futures.

**Input :**
```json
{"dedupe_key": "10.0.0.1:54321→1.2.3.4:443/TCP", "duration_hours": 24, "reason": "VPN connu"}
```
ou
```json
{"ip": "1.2.3.4", "duration_hours": 168, "reason": "Monitoring Datadog"}
```

**Stockage :** `~/.cache/mcp-flowsentinel/suppressions.jsonl`

**Critères d'acceptation :**
- [ ] Flow supprimé → `Fire()` l'ignore pendant `duration_hours`
- [ ] Suppression expirée → flow re-alerté normalement
- [ ] `get_alerts` filtre les flows supprimés par défaut (opt-in pour les voir)

---

## 2.6 — Outil MCP `get_threat_intel`

**Nouveau fichier :** `internal/tools/get_threat_intel.go`

**Objectif :** Query réputation d'une IP ou d'un hash JA3 à la demande.

**Input :** `{"ip": "1.2.3.4"}` ou `{"ja3_hash": "abc123..."}`

**Output :**
```json
{
  "ip": "1.2.3.4",
  "abuseipdb": {"confidence": 87, "reports": 234, "isp": "Vultr Holdings"},
  "geoip": {"country": "NL", "asn": "AS20473", "org": "Vultr Holdings LLC"},
  "ja3": null,
  "verdict": "HIGH_RISK",
  "sources": ["abuseipdb", "geoip", "local_history"]
}
```

**Critères d'acceptation :**
- [ ] IP privée → retourne "private IP, no lookup"
- [ ] AbuseIPDB désactivé → retourne GeoIP seul
- [ ] JA3 lookup dans base locale

---

## 2.7 — Outil MCP `export_flows`

**Nouveau fichier :** `internal/tools/export_flows.go`

**Objectif :** Exporter les flows au format CSV ou JSONL pour analyse externe (SIEM, Excel).

**Input :** mêmes filtres que `get_flow_history` + `format: "csv" | "jsonl"`

**Output :** string CSV ou JSONL, ou chemin vers fichier écrit sur disque.

**Critères d'acceptation :**
- [ ] CSV avec headers corrects
- [ ] JSONL valide ligne par ligne
- [ ] Filtres `min_score`, `src_ip`, `dst_ip`, `process_name` appliqués

---

---

# Phase 3 — Nouveaux Outils MCP (suite Phase 2)

Les outils `explain_flow`, `suppress_alert`, `get_threat_intel`, `export_flows` sont définis en Phase 2.

Outils additionnels Phase 3 :

---

## 3.1 — Outil MCP `scan_process`

**Nouveau fichier :** `internal/tools/scan_process.go`

**Objectif :** Deep-dive sécurité sur un processus : hash du binaire, signature numérique, réputation VirusTotal (si clé configurée), modules chargés.

**Output :**
```json
{
  "pid": 1234,
  "binary": "/tmp/evil.sh",
  "sha256": "abc123...",
  "signed": false,
  "virustotal_detections": 47,
  "loaded_modules": ["libssl.so.1.1", "libc.so.6"],
  "suspicious_signals": ["binary_in_tmp", "unsigned", "vt_positive"]
}
```

**Critères d'acceptation :**
- [ ] SHA256 du binaire calculé
- [ ] Signature vérifiée (Windows: Authenticode, Linux: RPM/deb sig)
- [ ] VirusTotal lookup si `intel.virustotal_api_key` configuré

---

## 3.2 — Outil MCP `live_watch`

**Nouveau fichier :** `internal/tools/live_watch.go`

**Objectif :** Surveiller un processus ou une IP en temps réel pendant N secondes, retourner les flows au fur et à mesure (streaming via MCP progress notifications).

**Input :** `{"process_name": "python", "duration_seconds": 30}`

**Critères d'acceptation :**
- [ ] Retourne des résultats intermédiaires toutes les 5s
- [ ] Résultat final = aggregate de toute la durée

---

---

# Phase 4 — Performance & Scalabilité

---

## 4.1 — Index en mémoire pour l'historique

**Fichier :** `internal/history/history.go`, `internal/history/index.go`

**Problème :** Full scan O(n) à chaque query.

**Approche :**
```go
// Index en mémoire chargé au démarrage
type HistoryIndex struct {
    mu       sync.RWMutex
    entries  []indexEntry  // (offset int64, timestamp time.Time, flowCount int)
}

type indexEntry struct {
    Offset    int64     // byte offset dans le fichier JSONL
    Timestamp time.Time
    FlowCount int
    MaxScore  float64
}

// Query : binary search sur timestamp pour trouver l'offset, seek direct
func (idx *HistoryIndex) QueryRange(from, to time.Time) []int64 { ... }
```

**Critères d'acceptation :**
- [ ] Query `max_age_hours: 1` sur fichier 50 MB → < 50ms
- [ ] Index reconstruit au démarrage en < 1s pour fichier 50 MB
- [ ] Append met à jour l'index en temps réel

---

## 4.2 — Eviction dedupMap avec LRU (remplace 0.1)

**Fichier :** `internal/alerting/alerting.go`

Si la Phase 0.1 implémente un cleanup périodique simple, la Phase 4 le remplace par le LRU existant (`internal/cache/lru.go`) :

```go
// Remplacer map[string]time.Time par *cache.LRU[string, time.Time]
var dedupCache = cache.NewLRU[string, time.Time](10000) // max 10K entrées
```

**Critères d'acceptation :**
- [ ] Jamais plus de 10K entrées en mémoire
- [ ] LRU évince les plus vieilles clés quand plein
- [ ] Performance identique ou meilleure

---

## 4.3 — Socket table avec cache différentiel

**Fichier :** `internal/correlate/correlate.go`

**Problème :** `BuildSocketTable()` = appel gopsutil complet toutes les 2s.

**Approche :** Maintenir la table en mémoire, la mettre à jour différentiellement (ajouter les nouveaux sockets, supprimer les fermés) via `/proc/net/tcp` directement sur Linux (beaucoup plus rapide que gopsutil).

```go
// Linux: lire /proc/net/tcp directement
// Windows: garder gopsutil mais réduire la fréquence à 5s
// Exposer LastRebuildDuration dans stats
```

**Critères d'acceptation :**
- [ ] Sur Linux, rebuild < 10ms pour 1000 connexions actives
- [ ] Précision identique à l'approche actuelle (test comparatif)

---

## 4.4 — Packet buffer adaptatif

**Fichier :** `internal/capture/capture.go`

**Problème :** Buffer fixe 4096. Trop petit sur interface 10 Gbps, trop grand sur loopback.

**Approche :**
```go
const (
    minChanBuffer     = 1024
    maxChanBuffer     = 65536
    targetFillRatio   = 0.7  // alerter si > 70% plein
)

// Taille initiale basée sur la vitesse de l'interface (si disponible via SIOCETHTOOL)
// Monitoring du ratio fill/capacity
```

**Critères d'acceptation :**
- [ ] Buffer size configurable dans config (`capture.packet_buffer_size`)
- [ ] Warning log si buffer > 70% plein pendant > 5s

---

## 4.5 — Compression historique

**Fichier :** `internal/history/history.go`

**Approche :** Compresser les entrées > 24h en gzip. Maintenir deux fichiers :
- `history.jsonl` — dernières 24h, non compressé, accès rapide
- `history.jsonl.gz` — 24h–7j, compressé, accès via décompression à la demande

**Critères d'acceptation :**
- [ ] Fichier 7j compressé < 20 MB (vs 350 MB non compressé)
- [ ] Query sur données compressées fonctionne (plus lent, mais possible)

---

---

# Phase 5 — Polish, README, Release

---

## 5.1 — README complet et honnête

**Sections à réécrire / ajouter :**

- **Limitations explicites** : "JA3 détecte les profils par défaut, pas les profils custom. Un attaquant qui randomize son JA3 n'est pas détecté."
- **Comportement sur échec webhook** : "Les échecs sont loggés sur stderr. 3 tentatives avec backoff. Après 3 échecs, l'alerte est perdue."
- **Faux positifs courants** : table avec les environnements et recommandations
- **Guide de tuning** : comment réduire le bruit en 5 minutes
- **Comparatif outillage** : tableau honnête vs Zeek/Suricata (forces ET limites)
- **Architecture de sécurité** : "le tool voit tout le trafic déchiffré — ne pas déployer sur réseau avec données sensibles sans contrôle d'accès"

---

## 5.2 — Tests d'intégration end-to-end

**Nouveau fichier :** `test/integration/`

**Scénarios :**
- Capture pcap avec beacon synthétique → score CRITICAL
- Capture pcap avec trafic normal → score LOW
- Config invalide → erreur claire
- Webhook test → POST reçu
- Restart avec config hot-reload → nouvelles valeurs actives

**Critères d'acceptation :**
- [ ] Coverage totale ≥ 80%
- [ ] Tests passent sans pcap réel (pcap synthétiques)
- [ ] CI green sur Linux, macOS, Windows

---

## 5.3 — Fuzzing des parsers

**Fichier :** `internal/capture/fuzz_test.go`, `internal/ja3/fuzz_test.go`

**Approche :** `go test -fuzz` sur les parsers critiques :
- Parser TLS ClientHello/ServerHello
- Parser DNS request/response
- Parser HTTP request
- Parser QUIC Initial

**Critères d'acceptation :**
- [ ] 10 minutes de fuzzing sans panic
- [ ] Corpus de base : 50 payloads réels

---

## 5.4 — Goreleaser + SBOM

**Fichier :** `.goreleaser.yml`

**Ajouter :**
- SBOM (Software Bill of Materials) généré automatiquement
- Signature Cosign des binaires
- Checksums SHA256 publiés avec chaque release
- Docker image multi-arch (linux/amd64, linux/arm64)

---

## 5.5 — Documentation des champs FlowRecord

**Nouveau fichier :** `docs/flow_record_schema.md`

Documenter chaque champ de `FlowRecord` avec :
- Type et range de valeurs
- Condition d'apparition (omitempty → quand est-il présent ?)
- Exemple de valeur réelle

---

---

# Récapitulatif des nouveaux champs `FlowRecord`

```go
type FlowRecord struct {
    // Existant
    SrcIP, DstIP, SrcPort, DstPort, Protocol string/uint16
    PacketCount, ByteCount int64
    FirstSeen, LastSeen time.Time
    SuspicionScore float64
    RiskLevel string
    SuspicionReasons, CleanSignals []string

    // Phase 1.1 — HTTP
    HTTPMethod      string   `json:"http_method,omitempty"`
    HTTPUserAgent   string   `json:"http_user_agent,omitempty"`
    HTTPHost        string   `json:"http_host,omitempty"`
    HTTPStatusCodes []int    `json:"http_status_codes,omitempty"`

    // Phase 1.2 — TLS avancé
    JA3SHash          string `json:"ja3s_hash,omitempty"`
    JA3SKnownBad      string `json:"ja3s_known_bad,omitempty"`
    TLSVersion        string `json:"tls_version,omitempty"`
    TLSCertSelfSigned bool   `json:"tls_cert_self_signed,omitempty"`
    TLSCertIssuer     string `json:"tls_cert_issuer,omitempty"`
    TLSCertExpiry     string `json:"tls_cert_expiry,omitempty"`

    // Phase 1.3 — DNS avancé
    DNSResponseCode int    `json:"dns_response_code,omitempty"`
    DNSTTL          uint32 `json:"dns_ttl,omitempty"`
    DNSQueryType    uint16 `json:"dns_query_type,omitempty"`

    // Phase 1.4 — QUIC
    IsQUIC bool `json:"is_quic,omitempty"`

    // Phase 1.5 — Réputation IP
    AbuseIPDBScore   int `json:"abuseipdb_score,omitempty"`
    AbuseIPDBReports int `json:"abuseipdb_reports,omitempty"`

    // Phase 1.8 — MITRE ATT&CK
    MITRETechniques []MITRETechnique `json:"mitre_techniques,omitempty"`

    // Phase 1.9 — Directionnel
    BytesSent     int64   `json:"bytes_sent"`
    BytesReceived int64   `json:"bytes_received"`
    UploadRatio   float64 `json:"upload_ratio,omitempty"`
}
```

---

# Récapitulatif des nouveaux champs `ScoringConfig`

```yaml
scoring:
  # Existant + nouveaux
  beaconing_min_interval_seconds: 5.0   # Phase 0.7
  exempted_cidrs: []                     # Phase 2.2
  internal_sensitive_ports: [22,135,389,445,636,3389]  # Phase 1.6
  disable_http_scoring: false            # Phase 1.1
  disable_lateral_movement_scoring: false # Phase 1.6
  disable_protocol_anomaly_scoring: false # Phase 1.7
  disable_quic_scoring: false            # Phase 1.4
  disable_dns_response_scoring: false    # Phase 1.3

intel:
  abuseipdb_api_key: ""                  # Phase 1.5
  abuseipdb_enabled: false
  abuseipdb_min_confidence: 20
  abuseipdb_cache_ttl_minutes: 60
  virustotal_api_key: ""                 # Phase 3.1

environment: "developer"                 # Phase 2.1 — developer|server|enterprise|container
```

---

# Checklist finale (Definition of Done)

- [ ] **Zéro bug connu** — tous les 10 bugs Phase 0 fixés avec tests régressifs
- [ ] **Coverage ≥ 80%** sur tous les packages
- [ ] **Zero data race** — `go test -race ./...` green
- [ ] **Build green** sur Linux / macOS / Windows (CI matrix)
- [ ] **False positive rate** — sur un poste de dev standard (Node.js, Docker, SSH), score médian < 3.0
- [ ] **JA3 database** ≥ 300 hashes client + 50 hashes server
- [ ] **MITRE ATT&CK** — tous les signaux mappés
- [ ] **README** — limitations honnêtes documentées, guide de tuning présent
- [ ] **Performance** — query historique 50 MB < 50ms, capture 10K paquets/s sans drop
- [ ] **AbuseIPDB** intégré avec graceful degradation
- [ ] **Nouveaux outils MCP** : `explain_flow`, `suppress_alert`, `get_threat_intel`, `export_flows`, `scan_process`

---

*Plan version 1.0 — 2026-04-14*  
*Auteur : Audit technique MCP-FlowSentinel*
