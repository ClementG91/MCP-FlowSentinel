package capture

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/ja3"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// droppedPackets counts OS-level dropped packets reported by pcap since startup.
var droppedPackets atomic.Uint64

// DroppedPackets returns the cumulative number of packets dropped by the kernel
// pcap ring buffer since the first live capture was started. A non-zero value
// means the capture interface is saturated and flows may be incomplete.
func DroppedPackets() uint64 { return droppedPackets.Load() }

// PacketEvent is emitted for each decoded packet of interest.
type PacketEvent struct {
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	Proto      string // "TCP" | "UDP"
	PayloadLen uint32
	Timestamp  time.Time
	// Optional enrichment — empty string means not present.
	DNSQuery      string // first question name from a DNS/UDP-53 packet
	TLSSNIName    string // server name from TLS ClientHello
	JA3Hash       string // JA3 fingerprint of TLS ClientHello, "" if not TLS
	IsQUIC        bool   // true when UDP 443 payload looks like a QUIC Initial packet
	// DNS response enrichment (port-53 responses only).
	DNSNXDomain   bool   // true when response code is NXDOMAIN (3)
	DNSMinRespTTL uint32 // minimum A/AAAA record TTL in the response; 0 means no A/AAAA answers
	// HTTP/1.1 enrichment (TCP only, first packet of a request/response).
	HTTPMethod    string // "GET", "POST", "CONNECT", … — "" if not HTTP
	HTTPHost      string // HTTP Host header value
	HTTPUserAgent string // HTTP User-Agent header value
	HTTPURI       string // HTTP request URI (first 256 chars)
	IsHTTP2       bool   // true when payload starts with the HTTP/2 client preface
	IsGRPC        bool   // true when 2+ consecutive gRPC Length-Prefixed Message frames detected
	// IPv6 extension header anomalies.
	IsIPv6RH0      bool // true when an IPv6 Routing Header type 0 was observed (deprecated, RFC 5095)
	IsIPv6Fragment bool // true when an IPv6 Fragment Header was observed
	// TLS server certificate (TCP 443 only, from ServerCertificate message).
	TLSCertInfo *CertInfo // non-nil when a server certificate was successfully parsed
}

// CapturePackets opens a live pcap handle on iface, applies an optional BPF
// filter and streams decoded PacketEvents until ctx is cancelled.
// The returned channel is closed when capture ends.
func CapturePackets(ctx context.Context, iface, bpfFilter string) (<-chan PacketEvent, error) {
	// 100 ms pcap read timeout lets us poll ctx at a reasonable rate.
	handle, err := pcap.OpenLive(iface, 65536, true, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("pcap OpenLive(%s): %w", iface, err)
	}

	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("BPF filter %q: %w", bpfFilter, err)
		}
	}

	ch := make(chan PacketEvent, 4096)
	go drainPackets(ctx, handle, ch, false)
	return ch, nil
}

// drainPackets is the shared packet-reading loop for both live and offline sources.
// When exitOnEOF is true (offline mode) the goroutine returns on io.EOF;
// otherwise errors (e.g. pcap read timeouts in live mode) are retried.
// In live mode, pcap Stats() are sampled every 5 seconds to detect kernel drops.
func drainPackets(ctx context.Context, handle *pcap.Handle, ch chan<- PacketEvent, exitOnEOF bool) {
	defer close(ch)
	defer handle.Close()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true

	// Tick for periodic drop-counter sampling (live captures only).
	var statsTicker <-chan time.Time
	if !exitOnEOF {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		statsTicker = t.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-statsTicker:
			if stats, err := handle.Stats(); err == nil {
				prev := droppedPackets.Swap(uint64(stats.PacketsDropped))
				if uint64(stats.PacketsDropped) > prev {
					log.Printf("capture: kernel dropped %d packets (total %d) — consider reducing capture load or increasing buffer",
						uint64(stats.PacketsDropped)-prev, stats.PacketsDropped)
				}
			}
		default:
		}

		pkt, err := src.NextPacket()
		if err != nil {
			if exitOnEOF && err == io.EOF {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		event := parsePacket(pkt)
		if event == nil {
			continue
		}

		select {
		case ch <- *event:
		case <-ctx.Done():
			return
		}
	}
}

// parsePacket extracts flow-level information from a raw gopacket.
func parsePacket(pkt gopacket.Packet) *PacketEvent {
	if pkt == nil {
		return nil
	}

	// Network layer — need source and destination IPs.
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return nil
	}

	var srcIP, dstIP net.IP
	switch nl := netLayer.(type) {
	case *layers.IPv4:
		srcIP = nl.SrcIP
		dstIP = nl.DstIP
	case *layers.IPv6:
		srcIP = nl.SrcIP
		dstIP = nl.DstIP
	default:
		return nil
	}

	// Transport layer — need ports and protocol.
	transLayer := pkt.TransportLayer()
	if transLayer == nil {
		return nil
	}

	var srcPort, dstPort uint16
	var proto string
	var payloadLen uint32
	var tcpPayload []byte

	switch tl := transLayer.(type) {
	case *layers.TCP:
		srcPort = uint16(tl.SrcPort)
		dstPort = uint16(tl.DstPort)
		proto = "TCP"
		payloadLen = uint32(len(tl.Payload))
		tcpPayload = tl.Payload
	case *layers.UDP:
		srcPort = uint16(tl.SrcPort)
		dstPort = uint16(tl.DstPort)
		proto = "UDP"
		payloadLen = uint32(len(tl.Payload))
		// Store UDP payload for QUIC detection below.
		if (srcPort == 443 || dstPort == 443) && len(tl.Payload) >= 5 {
			tcpPayload = tl.Payload // reuse variable — only set for UDP 443
		}
	default:
		return nil
	}

	ts := pkt.Metadata().Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	event := &PacketEvent{
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Proto:      proto,
		PayloadLen: payloadLen,
		Timestamp:  ts,
	}

	// DNS query + response extraction — port 53 only.
	if dstPort == 53 || srcPort == 53 {
		event.DNSQuery = extractDNSQuery(pkt)
		event.DNSNXDomain, event.DNSMinRespTTL = extractDNSResponse(pkt)
	}

	// TLS / HTTP enrichment — TCP only.
	if proto == "TCP" && len(tcpPayload) > 0 {
		// TLS ClientHello: SNI + JA3 fingerprint.
		event.TLSSNIName = extractTLSSNI(tcpPayload)
		event.JA3Hash = ja3.Fingerprint(tcpPayload)

		// TLS ServerCertificate: cert anomaly detection (inbound on 443/8443).
		if srcPort == 443 || srcPort == 8443 {
			event.TLSCertInfo = extractServerCert(tcpPayload)
		}

		// HTTP/2 preface detection.
		if IsHTTP2Preface(tcpPayload) {
			event.IsHTTP2 = true
			// gRPC frames appear after the HTTP/2 preface (24 bytes) in the same segment.
			if IsGRPCFrames(tcpPayload[24:]) {
				event.IsGRPC = true
			}
		} else if IsGRPCFrames(tcpPayload) {
			// gRPC on a mid-stream TCP segment (preface already exchanged earlier).
			event.IsGRPC = true
		}

		// HTTP/1.1 parsing (only when payload is not TLS — TLS records start 0x16).
		if !event.IsHTTP2 && len(tcpPayload) > 0 && tcpPayload[0] != 0x16 {
			if hi := extractHTTPInfo(tcpPayload); hi != nil {
				event.HTTPMethod = hi.Method
				event.HTTPHost = hi.Host
				event.HTTPUserAgent = hi.UserAgent
				event.HTTPURI = hi.URI
			}
		}
	}

	// QUIC detection — UDP 443 with a QUIC Initial packet long-header.
	if proto == "UDP" && (srcPort == 443 || dstPort == 443) {
		event.IsQUIC = isQUICInitial(tcpPayload)
	}

	// IPv6 extension headers — only present on IPv6 packets.
	// Routing Header type 0 (RH0) was deprecated by RFC 5095 due to source-routing
	// amplification attacks; its presence in modern traffic is anomalous.
	if rhLayer := pkt.Layer(layers.LayerTypeIPv6Routing); rhLayer != nil {
		if rh, ok := rhLayer.(*layers.IPv6Routing); ok && rh.RoutingType == 0 {
			event.IsIPv6RH0 = true
		}
	}
	if pkt.Layer(layers.LayerTypeIPv6Fragment) != nil {
		event.IsIPv6Fragment = true
	}

	return event
}

// isQUICInitial returns true if the payload starts with a QUIC v1 Initial long
// header. The check is intentionally lightweight: we look for the long-header
// bit (0x80) and the QUIC v1 version field (0x00000001) at bytes 1–4. This
// catches the overwhelming majority of QUIC connections without a full parser.
func isQUICInitial(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	// Long header: bit 7 must be set, bit 6 must be set (Fixed Bit for QUIC v1).
	if payload[0]&0xC0 != 0xC0 {
		return false
	}
	// QUIC version 1: bytes 1–4 = 0x00000001
	return payload[1] == 0x00 && payload[2] == 0x00 && payload[3] == 0x00 && payload[4] == 0x01
}

// extractDNSQuery returns the first question name from a DNS packet, or "".
func extractDNSQuery(pkt gopacket.Packet) string {
	dnsLayer := pkt.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return ""
	}
	dns, _ := dnsLayer.(*layers.DNS)
	if dns == nil || dns.QR || len(dns.Questions) == 0 {
		return "" // skip responses and empty queries
	}
	return string(dns.Questions[0].Name)
}

// extractDNSResponse inspects a DNS response packet (QR=1) and returns:
//   - nxdomain: true when the response code is NXDOMAIN (3)
//   - minTTL:   the minimum TTL of all A/AAAA records in the answer section;
//               0 means no A/AAAA records were present (e.g. pure NXDOMAIN)
func extractDNSResponse(pkt gopacket.Packet) (nxdomain bool, minTTL uint32) {
	dnsLayer := pkt.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns, _ := dnsLayer.(*layers.DNS)
	if dns == nil || !dns.QR {
		return // not a response
	}
	nxdomain = dns.ResponseCode == layers.DNSResponseCodeNXDomain
	// Track minimum TTL using a "found" flag instead of 0 as sentinel, because
	// TTL=0 is a valid value (instantaneous expiry, used in fast-flux DNS).
	// Using 0 as "not set" would incorrectly allow later higher-TTL records to
	// overwrite a legitimate TTL=0, causing us to miss the extreme fast-flux case.
	found := false
	for _, ans := range dns.Answers {
		if ans.Type == layers.DNSTypeA || ans.Type == layers.DNSTypeAAAA {
			if !found || ans.TTL < minTTL {
				minTTL = ans.TTL
				found = true
			}
		}
	}
	if !found {
		minTTL = 0 // caller convention: 0 means no A/AAAA records present
	}
	return
}

// extractTLSSNI parses a raw TCP payload looking for a TLS ClientHello and
// extracts the server_name extension value (SNI). Returns "" if not found.
// This is a lightweight hand-rolled parser that avoids the crypto/tls package
// so it can operate on arbitrary payloads without a full TLS handshake.
func extractTLSSNI(payload []byte) string {
	// TLS record header: type(1) version(2) length(2) — minimum 5 bytes.
	if len(payload) < 5 {
		return ""
	}
	// Record type 0x16 = Handshake.
	if payload[0] != 0x16 {
		return ""
	}
	recordLen := int(payload[3])<<8 | int(payload[4])
	if recordLen < 4 || len(payload) < 5+recordLen {
		return ""
	}
	// Handshake header: type(1) length(3) — skip to ClientHello body.
	hs := payload[5 : 5+recordLen]
	if hs[0] != 0x01 { // ClientHello
		return ""
	}
	// Skip: handshake type(1) + length(3) + client_version(2) + random(32).
	const hdrSkip = 1 + 3 + 2 + 32
	if len(hs) < hdrSkip+1 {
		return ""
	}
	pos := hdrSkip
	// Session ID length (variable).
	sessionIDLen := int(hs[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(hs) {
		return ""
	}
	// Cipher suites length.
	cipherLen := int(hs[pos])<<8 | int(hs[pos+1])
	pos += 2 + cipherLen
	if pos+1 > len(hs) {
		return ""
	}
	// Compression methods length.
	compLen := int(hs[pos])
	pos += 1 + compLen
	if pos+2 > len(hs) {
		return ""
	}
	// Extensions total length.
	extTotal := int(hs[pos])<<8 | int(hs[pos+1])
	pos += 2
	end := pos + extTotal
	if end > len(hs) {
		return ""
	}
	// Walk extensions looking for type 0x0000 (server_name).
	for pos+4 <= end {
		extType := uint16(hs[pos])<<8 | uint16(hs[pos+1])
		extLen := int(hs[pos+2])<<8 | int(hs[pos+3])
		pos += 4
		if pos+extLen > end {
			break
		}
		if extType == 0x0000 && extLen >= 5 {
			// SNI list length(2) + name type(1) + name length(2) + name.
			nameLen := int(hs[pos+3])<<8 | int(hs[pos+4])
			if pos+5+nameLen <= end {
				return string(hs[pos+5 : pos+5+nameLen])
			}
		}
		pos += extLen
	}
	return ""
}
