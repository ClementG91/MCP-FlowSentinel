// Package intel provides optional GeoIP and threat-intelligence enrichment.
//
// Set GEOIP_CITY_DB and/or GEOIP_ASN_DB to paths of MaxMind GeoLite2 MMDB
// files to enable country and ASN scoring. Free databases are available at
// https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
//
// Without env vars the package is a transparent no-op: Lookup returns nil
// and callers degrade gracefully.
package intel

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

// GeoInfo holds threat-intelligence resolved for a single IP address.
type GeoInfo struct {
	CountryCode string // ISO 3166-1 alpha-2, e.g. "US"
	CountryName string // e.g. "United States"
	ASN         uint   // Autonomous System Number
	OrgName     string // AS organisation name from MaxMind
	IsHighRisk  bool   // true when ASN matches the high-risk list
	RiskReason  string // human-readable explanation when IsHighRisk is true
}

var (
	initOnce sync.Once
	cityDB   *geoip2.Reader
	asnDB    *geoip2.Reader
	ipCache  sync.Map // string IP → *GeoInfo (nil = not found / no DB)
)

// Init loads MaxMind databases from GEOIP_CITY_DB and GEOIP_ASN_DB env vars.
// Call once at process start. Errors are silently ignored — the package
// degrades to a no-op when databases are missing or invalid.
func Init() {
	initOnce.Do(func() {
		if p := os.Getenv("GEOIP_CITY_DB"); p != "" {
			if r, err := geoip2.Open(p); err == nil {
				cityDB = r
			}
		}
		if p := os.Getenv("GEOIP_ASN_DB"); p != "" {
			if r, err := geoip2.Open(p); err == nil {
				asnDB = r
			}
		}
	})
}

// Enabled reports whether at least one database is loaded and active.
func Enabled() bool { return cityDB != nil || asnDB != nil }

// highRiskASNPatterns are lowercase substrings of MaxMind OrgName values for
// ASNs with documented histories of hosting malicious infrastructure.
// These are intentionally conservative — only well-documented bulletproof
// hosters are included, not general-purpose cloud providers.
// Sources: abuse.ch, Spamhaus ASN-DROP, public security research reports.
var highRiskASNPatterns = []string{
	"frantech",    // Frantech Solutions / BuyVM — bulletproof hosting
	"serverius",   // Serverius BV — known bulletproof hoster
	"hostsailor",  // HostSailor — abuse-tolerant hoster
	"quadranet",   // QuadraNet Enterprises — frequently hosts C2
	"shinjiru",    // Shinjiru Technology — bulletproof hoster
	"combahton",   // Combahton GmbH — bulletproof hosting
	"route48",     // Route48 — abuse-tolerant
	"privatelayer", // PrivateLayer Inc — bulletproof
	"psychz",      // Psychz Networks — frequently abused
}

// Lookup returns threat-intelligence for the given IP string, or nil if no
// database is loaded or the IP is not in the database.
// Results are cached in-process for the lifetime of the server.
func Lookup(ipStr string) *GeoInfo {
	if cityDB == nil && asnDB == nil {
		return nil
	}

	if v, ok := ipCache.Load(ipStr); ok {
		return v.(*GeoInfo) // may be nil (negative cache entry)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		ipCache.Store(ipStr, (*GeoInfo)(nil))
		return nil
	}

	info := &GeoInfo{}
	found := false

	if cityDB != nil {
		if rec, err := cityDB.City(ip); err == nil {
			info.CountryCode = rec.Country.IsoCode
			if n, ok := rec.Country.Names["en"]; ok {
				info.CountryName = n
			}
			found = true
		}
	}

	if asnDB != nil {
		if rec, err := asnDB.ASN(ip); err == nil {
			info.ASN = rec.AutonomousSystemNumber
			info.OrgName = rec.AutonomousSystemOrganization
			found = true

			orgLower := strings.ToLower(info.OrgName)
			for _, pat := range highRiskASNPatterns {
				if strings.Contains(orgLower, pat) {
					info.IsHighRisk = true
					info.RiskReason = fmt.Sprintf("ASN with documented abuse history: %s (AS%d)", info.OrgName, info.ASN)
					break
				}
			}
		}
	}

	if !found {
		ipCache.Store(ipStr, (*GeoInfo)(nil))
		return nil
	}

	ipCache.Store(ipStr, info)
	return info
}
