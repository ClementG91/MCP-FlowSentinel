package capture

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// buildTLSClientHello creates a minimal but valid TLS 1.2 ClientHello payload
// carrying the given SNI name so extractTLSSNI() will successfully parse it.
func buildTLSClientHello(sni string) []byte {
	// SNI extension body: list_length(2) + type(1) + name_length(2) + name
	sniBytes := []byte(sni)
	extBody := make([]byte, 2+1+2+len(sniBytes))
	binary.BigEndian.PutUint16(extBody[0:], uint16(1+2+len(sniBytes))) // server_name_list_length
	extBody[2] = 0x00                                                  // name_type = host_name
	binary.BigEndian.PutUint16(extBody[3:], uint16(len(sniBytes)))     // name_length
	copy(extBody[5:], sniBytes)

	// Extension: type(2) + length(2) + body
	ext := make([]byte, 4+len(extBody))
	binary.BigEndian.PutUint16(ext[0:], 0x0000) // extension_type = server_name
	binary.BigEndian.PutUint16(ext[2:], uint16(len(extBody)))
	copy(ext[4:], extBody)

	// TLS 1.2 ClientHello body:
	// client_version(2) + random(32) + session_id_len(1) +
	// cipher_suites_len(2) + cipher_suites(2) + compression_methods_len(1) +
	// compression_methods(1) + extensions_len(2) + extensions
	hello := make([]byte, 0, 64)
	hello = append(hello, 0x03, 0x03)             // TLS 1.2
	hello = append(hello, make([]byte, 32)...)     // random
	hello = append(hello, 0x00)                    // session_id_length = 0
	hello = append(hello, 0x00, 0x02)              // cipher_suites_length = 2
	hello = append(hello, 0x00, 0x2F)              // TLS_RSA_WITH_AES_128_CBC_SHA
	hello = append(hello, 0x01, 0x00)              // compression_methods_length=1, null
	hello = append(hello, 0x00, byte(len(ext)))    // extensions_length
	hello = append(hello, ext...)

	// Handshake header: type(1) + length(3)
	hs := make([]byte, 4+len(hello))
	hs[0] = 0x01 // ClientHello
	hs[1] = byte(len(hello) >> 16)
	hs[2] = byte(len(hello) >> 8)
	hs[3] = byte(len(hello))
	copy(hs[4:], hello)

	// TLS record: content_type(1) + version(2) + length(2) + fragment
	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16 // Handshake
	rec[1] = 0x03
	rec[2] = 0x01 // TLS 1.0 record layer
	binary.BigEndian.PutUint16(rec[3:], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

// buildTCPPacket creates a gopacket.Packet carrying a TCP segment with the
// given payload. seq is the TCP sequence number (for reassembly ordering).
func buildTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32, payload []byte, syn bool) gopacket.Packet {
	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		SYN:     syn,
		ACK:     !syn,
		Window:  65535,
	}
	tcp.SetNetworkLayerForChecksum(ipv4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ipv4, tcp, gopacket.Payload(payload)); err != nil {
		panic("buildTCPPacket: serialize: " + err.Error())
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

// ─── StreamReassembler tests ──────────────────────────────────────────────────

func TestStreamReassembler_WholeClientHello(t *testing.T) {
	// ClientHello fits in a single TCP segment — reassembler should still work.
	r, out := NewStreamReassembler()

	sni := "test.example.com"
	payload := buildTLSClientHello(sni)
	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")

	// SYN packet.
	r.Add(buildTCPPacket(src, dst, 54321, 443, 0, nil, true))
	// Data segment carrying the full ClientHello (seq=1 after SYN).
	r.Add(buildTCPPacket(src, dst, 54321, 443, 1, payload, false))
	r.FlushAll()

	select {
	case evt := <-out:
		if evt.TLSSNIName != sni {
			t.Errorf("SNI=%q, want %q", evt.TLSSNIName, sni)
		}
		if evt.Proto != "TCP" {
			t.Errorf("Proto=%q, want TCP", evt.Proto)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for reassembly result")
	}
}

func TestStreamReassembler_FragmentedClientHello(t *testing.T) {
	// Split the ClientHello across two TCP segments.
	r, out := NewStreamReassembler()

	sni := "fragmented.example.com"
	payload := buildTLSClientHello(sni)
	mid := len(payload) / 2
	part1 := payload[:mid]
	part2 := payload[mid:]

	src := net.ParseIP("192.168.1.1")
	dst := net.ParseIP("192.168.1.2")

	r.Add(buildTCPPacket(src, dst, 12345, 443, 0, nil, true))
	r.Add(buildTCPPacket(src, dst, 12345, 443, 1, part1, false))
	r.Add(buildTCPPacket(src, dst, 12345, 443, uint32(1+len(part1)), part2, false))
	r.FlushAll()

	select {
	case evt := <-out:
		if evt.TLSSNIName != sni {
			t.Errorf("fragmented SNI=%q, want %q", evt.TLSSNIName, sni)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for fragmented reassembly result")
	}
}

func TestStreamReassembler_NonTLS_NoResult(t *testing.T) {
	// HTTP payload — reassembler should not emit anything.
	r, out := NewStreamReassembler()

	src := net.ParseIP("10.0.0.3")
	dst := net.ParseIP("10.0.0.4")
	httpPayload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	r.Add(buildTCPPacket(src, dst, 11111, 80, 0, nil, true))
	r.Add(buildTCPPacket(src, dst, 11111, 80, 1, httpPayload, false))
	r.FlushAll()

	select {
	case evt := <-out:
		t.Errorf("unexpected reassembly result for HTTP payload: SNI=%q", evt.TLSSNIName)
	case <-time.After(100 * time.Millisecond):
		// Correct — no SNI emitted for non-TLS traffic.
	}
}

func TestStreamReassembler_BufferCap_NoPanic(t *testing.T) {
	// Feed maxStreamBuf+extra bytes — reassembler must not panic or allocate unbounded.
	r, _ := NewStreamReassembler()

	src := net.ParseIP("10.1.0.1")
	dst := net.ParseIP("10.1.0.2")
	bigPayload := make([]byte, maxStreamBuf+1024)
	for i := range bigPayload {
		bigPayload[i] = byte(i)
	}

	r.Add(buildTCPPacket(src, dst, 55555, 443, 0, nil, true))
	seq := uint32(1)
	chunkSize := 1400
	for i := 0; i < len(bigPayload); i += chunkSize {
		end := i + chunkSize
		if end > len(bigPayload) {
			end = len(bigPayload)
		}
		r.Add(buildTCPPacket(src, dst, 55555, 443, seq, bigPayload[i:end], false))
		seq += uint32(end - i)
	}
	r.FlushAll()
	// If we reach here without panic, the test passes.
}

func TestStreamReassembler_FlushOlderThan_NoPanic(t *testing.T) {
	r, _ := NewStreamReassembler()
	// Should not panic on an empty pool.
	r.FlushOlderThan(time.Now())
	r.FlushAll()
}

func TestStreamReassembler_MultipleStreams(t *testing.T) {
	// Two simultaneous streams — each should get its own SNI result.
	r, out := NewStreamReassembler()

	src1 := net.ParseIP("10.0.1.1")
	src2 := net.ParseIP("10.0.1.2")
	dst := net.ParseIP("10.0.1.100")
	sni1 := "stream1.example.com"
	sni2 := "stream2.example.com"

	r.Add(buildTCPPacket(src1, dst, 1001, 443, 0, nil, true))
	r.Add(buildTCPPacket(src2, dst, 1002, 443, 0, nil, true))
	r.Add(buildTCPPacket(src1, dst, 1001, 443, 1, buildTLSClientHello(sni1), false))
	r.Add(buildTCPPacket(src2, dst, 1002, 443, 1, buildTLSClientHello(sni2), false))
	r.FlushAll()

	seen := map[string]bool{}
	deadline := time.After(500 * time.Millisecond)
	for len(seen) < 2 {
		select {
		case evt := <-out:
			seen[evt.TLSSNIName] = true
		case <-deadline:
			t.Errorf("timeout — only received SNIs: %v, want both %q and %q", seen, sni1, sni2)
			return
		}
	}
	if !seen[sni1] {
		t.Errorf("did not receive SNI %q", sni1)
	}
	if !seen[sni2] {
		t.Errorf("did not receive SNI %q", sni2)
	}
}

