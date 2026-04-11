package capture

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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
	DNSQuery   string // first question name from a DNS/UDP-53 packet
	TLSSNIName string // server name from TLS ClientHello
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
func drainPackets(ctx context.Context, handle *pcap.Handle, ch chan<- PacketEvent, exitOnEOF bool) {
	defer close(ch)
	defer handle.Close()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true

	for {
		select {
		case <-ctx.Done():
			return
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

	// DNS query extraction — UDP/TCP port 53.
	if dstPort == 53 || srcPort == 53 {
		event.DNSQuery = extractDNSQuery(pkt)
	}

	// TLS SNI extraction — TCP port 443 (or any other HTTPS-like port).
	if proto == "TCP" && len(tcpPayload) > 0 {
		event.TLSSNIName = extractTLSSNI(tcpPayload)
	}

	return event
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
