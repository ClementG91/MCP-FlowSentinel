package intel

import (
	"net"
	"os"
	"sync"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// resetState clears the singleton so each test starts from a clean slate.
// It also closes open DB readers to avoid leaked file handles on Windows.
func resetState() {
	if cityDB != nil {
		cityDB.Close()
	}
	if asnDB != nil {
		asnDB.Close()
	}
	initOnce = sync.Once{}
	cityDB = nil
	asnDB = nil
	ipCache = sync.Map{}
}

// buildCityMMDB writes a minimal GeoLite2-City MMDB file containing one /24
// subnet (8.8.8.0/24 → country US / United States) and returns its path.
func buildCityMMDB(t *testing.T) string {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "GeoLite2-City"})
	if err != nil {
		t.Fatalf("mmdbwriter.New: %v", err)
	}
	_, network, err := net.ParseCIDR("8.8.8.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	if err := w.Insert(network, mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String("US"),
			"names": mmdbtype.Map{
				"en": mmdbtype.String("United States"),
			},
		},
	}); err != nil {
		t.Fatalf("Insert city: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "city-*.mmdb")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := w.WriteTo(f); err != nil {
		f.Close()
		t.Fatalf("WriteTo: %v", err)
	}
	f.Close()
	return f.Name()
}

// buildASNMMDB writes a minimal GeoLite2-ASN MMDB file containing one /24
// subnet (8.8.8.0/24 → AS15169 orgName) and returns its path.
func buildASNMMDB(t *testing.T, orgName string) string {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "GeoLite2-ASN"})
	if err != nil {
		t.Fatalf("mmdbwriter.New: %v", err)
	}
	_, network, err := net.ParseCIDR("8.8.8.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	if err := w.Insert(network, mmdbtype.Map{
		"autonomous_system_number":       mmdbtype.Uint32(15169),
		"autonomous_system_organization": mmdbtype.String(orgName),
	}); err != nil {
		t.Fatalf("Insert ASN: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "asn-*.mmdb")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := w.WriteTo(f); err != nil {
		f.Close()
		t.Fatalf("WriteTo: %v", err)
	}
	f.Close()
	return f.Name()
}

// ─── No-DB behaviour ─────────────────────────────────────────────────────────

func TestEnabled_NoDatabases_ReturnsFalse(t *testing.T) {
	resetState()
	Init()
	if Enabled() {
		t.Error("Enabled() = true with no databases loaded, want false")
	}
}

func TestLookup_NoDatabases_ReturnsNil(t *testing.T) {
	resetState()
	Init()

	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "192.168.1.1", "::1"} {
		if got := Lookup(ip); got != nil {
			t.Errorf("Lookup(%q) = %+v, want nil when no DB loaded", ip, got)
		}
	}
}

func TestLookup_InvalidIP_ReturnsNil(t *testing.T) {
	resetState()
	Init()

	invalids := []string{"", "not-an-ip", "999.999.999.999", "256.0.0.1"}
	for _, ip := range invalids {
		if got := Lookup(ip); got != nil {
			t.Errorf("Lookup(%q) = %+v, want nil for invalid IP", ip, got)
		}
	}
}

// ─── Negative cache ───────────────────────────────────────────────────────────

// TestLookup_NoDB_DoesNotPopulateCache verifies that when no database is loaded
// Lookup takes the early-exit path and does not write stale entries to the cache.
// This ensures that if a DB is loaded later (e.g. hot-reload), the first real
// lookup is not blocked by a cached nil from the no-DB phase.
func TestLookup_NoDB_DoesNotPopulateCache(t *testing.T) {
	resetState()
	Init() // no DBs → Enabled() = false

	ip := "8.8.8.8"

	result := Lookup(ip)
	if result != nil {
		t.Fatalf("Lookup(%q) = %+v, want nil", ip, result)
	}

	// The fast-path must NOT store anything in the cache so a future call with
	// a real DB can still execute a fresh lookup.
	if _, cached := ipCache.Load(ip); cached {
		t.Error("Lookup should not populate cache when no DB is loaded")
	}
}

// ─── Init idempotency ─────────────────────────────────────────────────────────

func TestInit_Idempotent(t *testing.T) {
	resetState()

	// Call Init multiple times — only the first should actually run.
	Init()
	Init()
	Init()

	if Enabled() {
		t.Error("Enabled() = true after multiple Init() calls with no env vars")
	}
}

// ─── Init with invalid DB path ────────────────────────────────────────────────

func TestInit_InvalidDBPath_Silently_Degrades(t *testing.T) {
	resetState()
	t.Setenv("GEOIP_CITY_DB", "/nonexistent/path/GeoLite2-City.mmdb")
	t.Setenv("GEOIP_ASN_DB", "/nonexistent/path/GeoLite2-ASN.mmdb")

	Init() // must not panic or log fatally

	if Enabled() {
		t.Error("Enabled() = true with invalid DB paths, want false")
	}
	if Lookup("8.8.8.8") != nil {
		t.Error("Lookup should return nil when DB failed to load")
	}
}

// ─── Integration test (skipped without real MMDB files) ──────────────────────

// TestLookup_WithRealDBs is an integration test that exercises the full GeoIP
// lookup path. It is skipped unless both GEOIP_CITY_DB and GEOIP_ASN_DB are
// set in the environment and point to valid MaxMind GeoLite2 MMDB files.
func TestLookup_WithRealDBs(t *testing.T) {
	cityPath := os.Getenv("GEOIP_CITY_DB")
	asnPath := os.Getenv("GEOIP_ASN_DB")
	if cityPath == "" || asnPath == "" {
		t.Skip("GEOIP_CITY_DB and GEOIP_ASN_DB not set — skipping integration test")
	}

	resetState()
	Init()

	if !Enabled() {
		t.Fatal("Enabled() = false even with DB env vars set")
	}

	// Google Public DNS — should always resolve to a valid entry.
	info := Lookup("8.8.8.8")
	if info == nil {
		t.Fatal("Lookup(8.8.8.8) returned nil with real DB")
	}
	if info.CountryCode == "" {
		t.Error("CountryCode is empty for 8.8.8.8")
	}
	t.Logf("8.8.8.8: country=%s asn=%d org=%q high_risk=%v",
		info.CountryCode, info.ASN, info.OrgName, info.IsHighRisk)

	// Cache hit — second call must return the same pointer.
	info2 := Lookup("8.8.8.8")
	if info2 != info {
		t.Error("second Lookup should return cached pointer, got different value")
	}
}

// ─── Fake-MMDB tests (city DB) ────────────────────────────────────────────────
//
// Each test registers t.Cleanup(resetState) AFTER t.TempDir is called inside
// buildCityMMDB/buildASNMMDB. Because t.Cleanup is LIFO, resetState (which
// closes open DB file handles) runs before the t.TempDir removal, preventing
// "Access is denied" errors on Windows.

func TestInit_WithCityDB_SetsEnabled(t *testing.T) {
	resetState()
	cityPath := buildCityMMDB(t)
	t.Setenv("GEOIP_CITY_DB", cityPath)
	t.Cleanup(resetState)
	Init()
	if !Enabled() {
		t.Error("Enabled() = false after loading valid city DB, want true")
	}
}

func TestLookup_WithCityDB_ReturnsCountry(t *testing.T) {
	resetState()
	cityPath := buildCityMMDB(t)
	t.Setenv("GEOIP_CITY_DB", cityPath)
	t.Cleanup(resetState)
	Init()

	info := Lookup("8.8.8.8")
	if info == nil {
		t.Fatal("Lookup(8.8.8.8) = nil, want non-nil with city DB loaded")
	}
	if info.CountryCode != "US" {
		t.Errorf("CountryCode = %q, want US", info.CountryCode)
	}
	if info.CountryName != "United States" {
		t.Errorf("CountryName = %q, want United States", info.CountryName)
	}
}

func TestLookup_WithCityDB_CacheHit_ReturnsSamePointer(t *testing.T) {
	resetState()
	cityPath := buildCityMMDB(t)
	t.Setenv("GEOIP_CITY_DB", cityPath)
	t.Cleanup(resetState)
	Init()

	first := Lookup("8.8.8.8")
	if first == nil {
		t.Fatal("Lookup(8.8.8.8) = nil unexpectedly")
	}
	second := Lookup("8.8.8.8")
	if first != second {
		t.Error("second Lookup should return cached pointer, got different value")
	}
}

func TestLookup_WithCityDB_InvalidIPWhenDBLoaded_ReturnsNil(t *testing.T) {
	resetState()
	cityPath := buildCityMMDB(t)
	t.Setenv("GEOIP_CITY_DB", cityPath)
	t.Cleanup(resetState)
	Init()

	// With DB loaded, invalid IP must return nil (ip==nil branch in Lookup).
	for _, bad := range []string{"not-an-ip", "999.999.999.999"} {
		if got := Lookup(bad); got != nil {
			t.Errorf("Lookup(%q) = %+v, want nil for invalid IP with DB loaded", bad, got)
		}
	}
}

// ─── Fake-MMDB tests (ASN DB) ─────────────────────────────────────────────────

func TestInit_WithASNDB_SetsEnabled(t *testing.T) {
	resetState()
	asnPath := buildASNMMDB(t, "GOOGLE")
	t.Setenv("GEOIP_ASN_DB", asnPath)
	t.Cleanup(resetState)
	Init()
	if !Enabled() {
		t.Error("Enabled() = false after loading valid ASN DB, want true")
	}
}

func TestLookup_WithASNDB_ReturnsASNInfo(t *testing.T) {
	resetState()
	asnPath := buildASNMMDB(t, "GOOGLE")
	t.Setenv("GEOIP_ASN_DB", asnPath)
	t.Cleanup(resetState)
	Init()

	info := Lookup("8.8.8.8")
	if info == nil {
		t.Fatal("Lookup(8.8.8.8) = nil, want non-nil with ASN DB loaded")
	}
	if info.ASN != 15169 {
		t.Errorf("ASN = %d, want 15169", info.ASN)
	}
	if info.OrgName != "GOOGLE" {
		t.Errorf("OrgName = %q, want GOOGLE", info.OrgName)
	}
	if info.IsHighRisk {
		t.Error("GOOGLE should not be flagged as high-risk")
	}
}

func TestLookup_WithASNDB_HighRiskOrg_SetsFlag(t *testing.T) {
	resetState()
	asnPath := buildASNMMDB(t, "FranTech Solutions")
	t.Setenv("GEOIP_ASN_DB", asnPath)
	t.Cleanup(resetState)
	Init()

	info := Lookup("8.8.8.8")
	if info == nil {
		t.Fatal("Lookup(8.8.8.8) = nil, want non-nil")
	}
	if !info.IsHighRisk {
		t.Error("FranTech Solutions should be flagged as high-risk")
	}
	if info.RiskReason == "" {
		t.Error("RiskReason should be non-empty for high-risk ASN")
	}
}

func TestLookup_WithASNDB_CacheHit_ReturnsSamePointer(t *testing.T) {
	resetState()
	asnPath := buildASNMMDB(t, "TEST-ORG")
	t.Setenv("GEOIP_ASN_DB", asnPath)
	t.Cleanup(resetState)
	Init()

	first := Lookup("8.8.8.8")
	if first == nil {
		t.Fatal("first Lookup returned nil unexpectedly")
	}
	second := Lookup("8.8.8.8")
	if first != second {
		t.Error("second Lookup should return cached pointer")
	}
}

// ─── Fake-MMDB tests (both DBs) ───────────────────────────────────────────────

func TestLookup_WithBothDBs_ReturnsFullInfo(t *testing.T) {
	resetState()
	cityPath := buildCityMMDB(t)
	asnPath := buildASNMMDB(t, "GOOGLE")
	t.Setenv("GEOIP_CITY_DB", cityPath)
	t.Setenv("GEOIP_ASN_DB", asnPath)
	t.Cleanup(resetState)
	Init()

	info := Lookup("8.8.8.8")
	if info == nil {
		t.Fatal("Lookup(8.8.8.8) = nil with both DBs loaded")
	}
	if info.CountryCode != "US" {
		t.Errorf("CountryCode = %q, want US", info.CountryCode)
	}
	if info.OrgName != "GOOGLE" {
		t.Errorf("OrgName = %q, want GOOGLE", info.OrgName)
	}
}

func TestLookup_WithCityDB_IPNotInDB_ReturnsCachedResult(t *testing.T) {
	// DB contains only 8.8.8.0/24. Looking up an IP outside that range returns
	// a non-nil but empty GeoInfo (geoip2 returns success with zero-value record).
	// Verifies that the result is cached and the second call returns the same pointer.
	resetState()
	cityPath := buildCityMMDB(t)
	t.Setenv("GEOIP_CITY_DB", cityPath)
	t.Cleanup(resetState)
	Init()

	// 1.2.3.4 is not in the fake DB → empty but non-nil result.
	got := Lookup("1.2.3.4")
	// Second call must hit the cache and return the same pointer.
	got2 := Lookup("1.2.3.4")
	if got != got2 {
		t.Error("second Lookup should return cached pointer, got different value")
	}
	t.Logf("1.2.3.4 lookup result: %+v", got)
}

func TestLookup_WithBothDBs_HighRisk_CombinesInfo(t *testing.T) {
	resetState()
	cityPath := buildCityMMDB(t)
	asnPath := buildASNMMDB(t, "Frantech Solutions")
	t.Setenv("GEOIP_CITY_DB", cityPath)
	t.Setenv("GEOIP_ASN_DB", asnPath)
	t.Cleanup(resetState)
	Init()

	info := Lookup("8.8.8.8")
	if info == nil {
		t.Fatal("Lookup returned nil")
	}
	if info.CountryCode != "US" {
		t.Errorf("CountryCode = %q, want US", info.CountryCode)
	}
	if !info.IsHighRisk {
		t.Error("Frantech Solutions should be high-risk")
	}
}
