package capture

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ─── TLS SNI extraction ───────────────────────────────────────────────────────

// buildClientHello constructs a minimal but syntactically valid TLS 1.2
// ClientHello record containing a single server_name extension for hostname.
func buildClientHello(hostname string) []byte {
	name := []byte(hostname)

	// SNI extension data:
	//   list_length (2) | name_type (1) | name_length (2) | name
	listLen := 1 + 2 + len(name) // name_type + name_length field + name bytes
	sniData := make([]byte, 0, 2+1+2+len(name))
	sniData = append(sniData,
		byte(listLen>>8), byte(listLen),
		0x00,                              // name_type = host_name
		byte(len(name)>>8), byte(len(name)),
	)
	sniData = append(sniData, name...)

	// SNI extension with type/length header (type=0x0000)
	sniExt := make([]byte, 0, 4+len(sniData))
	sniExt = append(sniExt,
		0x00, 0x00, // extension type = server_name
		byte(len(sniData)>>8), byte(len(sniData)),
	)
	sniExt = append(sniExt, sniData...)

	// ClientHello body
	var body []byte
	body = append(body, 0x03, 0x03)          // client_version = TLS 1.2
	body = append(body, make([]byte, 32)...) // random (32 bytes)
	body = append(body, 0x00)                // session_id_len = 0
	body = append(body,
		0x00, 0x02, // cipher_suites_len = 2
		0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0x01, 0x00, // comp_methods_len=1, null compression
		byte(len(sniExt)>>8), byte(len(sniExt)), // extensions_total_len
	)
	body = append(body, sniExt...)

	// Handshake header: type(1) + body_len(3)
	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, 0x01) // ClientHello
	hs = append(hs,
		byte(len(body)>>16),
		byte(len(body)>>8),
		byte(len(body)),
	)
	hs = append(hs, body...)

	// TLS record: content_type(1) + version(2) + record_len(2) + data
	record := make([]byte, 0, 5+len(hs))
	record = append(record, 0x16)       // ContentType = Handshake
	record = append(record, 0x03, 0x01) // TLS 1.0 record version
	record = append(record, byte(len(hs)>>8), byte(len(hs)))
	record = append(record, hs...)
	return record
}

func TestExtractTLSSNI(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{
			name:    "valid ClientHello with SNI",
			payload: buildClientHello("example.com"),
			want:    "example.com",
		},
		{
			name:    "valid ClientHello long hostname",
			payload: buildClientHello("very.long.subdomain.example.internal.corp"),
			want:    "very.long.subdomain.example.internal.corp",
		},
		{
			name:    "empty payload",
			payload: []byte{},
			want:    "",
		},
		{
			name:    "too short to be TLS",
			payload: []byte{0x16, 0x03},
			want:    "",
		},
		{
			name:    "wrong content type (Application Data, not Handshake)",
			payload: append([]byte{0x17, 0x03, 0x03, 0x00, 0x05}, make([]byte, 5)...),
			want:    "",
		},
		{
			name:    "Handshake type but not ClientHello (ServerHello=0x02)",
			payload: func() []byte { b := buildClientHello("x.com"); b[5] = 0x02; return b }(),
			want:    "",
		},
		{
			name:    "truncated after record header",
			payload: []byte{0x16, 0x03, 0x01, 0x00, 0x10}, // record_len=16 but no data
			want:    "",
		},
		{
			name:    "random bytes",
			payload: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03},
			want:    "",
		},
		{
			// TLS record header valid, handshake type = ClientHello (0x01),
			// but body too short to skip past hdrSkip (1+3+2+32 = 38 bytes).
			name: "ClientHello body too short for hdrSkip",
			payload: func() []byte {
				hs := make([]byte, 11) // recordLen=11, >= 4
				hs[0] = 0x01           // ClientHello
				rec := []byte{0x16, 0x03, 0x03, 0, byte(len(hs))}
				return append(rec, hs...)
			}(),
			want: "",
		},
		{
			// Valid ClientHello up to session ID, but session ID consumes remaining bytes.
			name: "ClientHello truncated in session ID area",
			payload: func() []byte {
				// Build hs: type(1) + length(3) + version(2) + random(32) + sessionIDLen(1)
				// Total = 39 bytes — just enough to pass hdrSkip+1 check, but
				// pos+2 will exceed len(hs) when reading cipher suites length.
				hs := make([]byte, 39)
				hs[0] = 0x01 // ClientHello
				// hs[38] = sessionIDLen = 0 → pos advances by 1; pos+2 = 41 > 39 → return ""
				rec := []byte{0x16, 0x03, 0x03, 0, byte(len(hs))}
				return append(rec, hs...)
			}(),
			want: "",
		},
		{
			// Valid ClientHello up to cipher suites, but payload cut before comp methods len byte.
			// Triggers: pos+1 > len(hs) after cipherLen skip.
			name: "ClientHello truncated after cipher suites",
			payload: func() []byte {
				// type(1)+len(3)+version(2)+random(32)+sessionID(1) = 39 bytes,
				// then cipher len(2)+cipher(2) = 4 more = 43 total. Stop here.
				hs := make([]byte, 43)
				hs[0] = 0x01 // ClientHello
				// version = TLS1.2
				hs[4+1] = 0x03
				hs[4+2] = 0x03
				// sessionIDLen = 0 (byte at index 38)
				// cipherLen at index 39,40 = 0x00, 0x02 (2 bytes cipher data)
				hs[39] = 0x00
				hs[40] = 0x02
				// cipher at 41,42 — leave as zeros
				// NO compression methods byte — pos+1 > len(hs) triggers here
				rec := []byte{0x16, 0x03, 0x03, 0, byte(len(hs))}
				return append(rec, hs...)
			}(),
			want: "",
		},
		{
			// ClientHello truncated before extensions length (2 bytes).
			// Triggers: pos+2 > len(hs) after comp methods skip.
			name: "ClientHello truncated after compression methods",
			payload: func() []byte {
				// type(1)+len(3)+version(2)+random(32)+sessionID(1) = 39,
				// cipherLen(2)+cipher(2)=4, compLen(1)+comp(1)=2 → 46 bytes total.
				// One byte for compLen but NO extensions length bytes.
				hs := make([]byte, 45)
				hs[0] = 0x01 // ClientHello
				hs[4+1] = 0x03
				hs[4+2] = 0x03
				// sessionIDLen = 0 at index 38
				// cipherLen at 39,40 = 0x00, 0x02
				hs[39] = 0x00
				hs[40] = 0x02
				// compLen at 43 = 0x01, comp method = 0x00 at 44
				hs[43] = 0x01
				hs[44] = 0x00
				// Now pos+2 = 46 > len(hs)=45 → triggers truncation check
				rec := []byte{0x16, 0x03, 0x03, 0, byte(len(hs))}
				return append(rec, hs...)
			}(),
			want: "",
		},
		{
			// Extension overflows: extension claims extLen that would exceed extensions area.
			// Triggers: pos+extLen > end { break }.
			name: "Extension body overflows extensions area",
			payload: func() []byte {
				// Single extension: type=0xff00, length=255 but extensions area is only 10 bytes.
				var exts []byte
				exts = append(exts, 0xff, 0x00) // ext type
				exts = append(exts, 0x00, 0xff) // ext len = 255 (much larger than available)
				// Only 4 bytes of extension data follow (total ext area = 8 bytes, but extLen=255)
				exts = append(exts, 0x00, 0x00, 0x00, 0x00)

				var body []byte
				body = append(body, 0x03, 0x03)
				body = append(body, make([]byte, 32)...)
				body = append(body, 0x00)
				body = append(body, 0x00, 0x02, 0xc0, 0x2b)
				body = append(body, 0x01, 0x00)
				body = append(body, byte(len(exts)>>8), byte(len(exts)))
				body = append(body, exts...)

				hs := []byte{0x01}
				hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
				hs = append(hs, body...)

				rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
				return append(rec, hs...)
			}(),
			want: "",
		},
		{
			// SNI extension present but extLen < 5 (too short to hold all SNI fields).
			// Triggers: extType == 0x0000 && extLen >= 5 → false → pos += extLen.
			name: "SNI extension too short (extLen < 5)",
			payload: func() []byte {
				// SNI ext type=0x0000, extLen=2, data=0x00,0x00 (valid length but too short)
				var exts []byte
				exts = append(exts, 0x00, 0x00) // SNI ext type
				exts = append(exts, 0x00, 0x02) // extLen = 2 (< 5)
				exts = append(exts, 0x00, 0x00) // 2 bytes of data

				var body []byte
				body = append(body, 0x03, 0x03)
				body = append(body, make([]byte, 32)...)
				body = append(body, 0x00)
				body = append(body, 0x00, 0x02, 0xc0, 0x2b)
				body = append(body, 0x01, 0x00)
				body = append(body, byte(len(exts)>>8), byte(len(exts)))
				body = append(body, exts...)

				hs := []byte{0x01}
				hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
				hs = append(hs, body...)

				rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
				return append(rec, hs...)
			}(),
			want: "",
		},
		{
			// SNI extension valid type+length but nameLen overflows the SNI data area.
			// Triggers: pos+5+nameLen <= end → false.
			name: "SNI name length overflows extension data",
			payload: func() []byte {
				// SNI ext: listLen(2)+nameType(1)+nameLen(2) = 5 bytes, nameLen=255 but no data
				sniData := []byte{
					0x00, 0x05, // listLen = 5 (only the 5-byte header, no name bytes)
					0x00,       // name_type = host_name
					0x00, 0xff, // nameLen = 255 (but no 255 bytes follow)
				}
				var exts []byte
				exts = append(exts, 0x00, 0x00) // SNI ext type
				exts = append(exts, byte(len(sniData)>>8), byte(len(sniData)))
				exts = append(exts, sniData...)

				var body []byte
				body = append(body, 0x03, 0x03)
				body = append(body, make([]byte, 32)...)
				body = append(body, 0x00)
				body = append(body, 0x00, 0x02, 0xc0, 0x2b)
				body = append(body, 0x01, 0x00)
				body = append(body, byte(len(exts)>>8), byte(len(exts)))
				body = append(body, exts...)

				hs := []byte{0x01}
				hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
				hs = append(hs, body...)

				rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
				return append(rec, hs...)
			}(),
			want: "",
		},
		{
			// extTotal in the ClientHello claims more bytes than the actual handshake
			// body. Triggers: end > len(hs) { return "" } (pre-loop overflow check).
			name: "Extensions total length overflows handshake body",
			payload: func() []byte {
				var body []byte
				body = append(body, 0x03, 0x03)          // client_version TLS 1.2
				body = append(body, make([]byte, 32)...) // random
				body = append(body, 0x00)                // session_id_len = 0
				body = append(body, 0x00, 0x02, 0xc0, 0x2b) // cipher suites (2 bytes)
				body = append(body, 0x01, 0x00)          // comp_methods len=1, method=null
				// extTotal = 0x01, 0x00 = 256, but only 4 real bytes follow.
				body = append(body, 0x01, 0x00)
				body = append(body, 0x00, 0x00, 0x00, 0x00) // 4 bytes of ext data (not 256)

				hs := []byte{0x01}
				hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
				hs = append(hs, body...)

				rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
				return append(rec, hs...)
			}(),
			want: "",
		},
		{
			// Extension type != 0x0000 forces the loop to advance via `pos += extLen`
			// before finding the SNI extension. Tests the non-SNI extension skip path.
			name: "ClientHello with non-SNI extension before SNI",
			payload: func() []byte {
				name := []byte("multi-ext.example.com")
				listLen := 1 + 2 + len(name)
				sniData := []byte{byte(listLen >> 8), byte(listLen), 0x00, byte(len(name) >> 8), byte(len(name))}
				sniData = append(sniData, name...)
				sniExt := []byte{0x00, 0x00, byte(len(sniData) >> 8), byte(len(sniData))}
				sniExt = append(sniExt, sniData...)

				// A dummy extension (type 0xff01, 2 bytes of data).
				dummyExt := []byte{0xff, 0x01, 0x00, 0x02, 0x00, 0x00}

				allExts := append(dummyExt, sniExt...)
				var body []byte
				body = append(body, 0x03, 0x03)          // version TLS 1.2
				body = append(body, make([]byte, 32)...) // random
				body = append(body, 0x00)                // session_id_len = 0
				body = append(body, 0x00, 0x02, 0xc0, 0x2b) // cipher suites
				body = append(body, 0x01, 0x00)          // comp methods
				body = append(body, byte(len(allExts)>>8), byte(len(allExts)))
				body = append(body, allExts...)

				hs := []byte{0x01}
				hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
				hs = append(hs, body...)

				rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
				return append(rec, hs...)
			}(),
			want: "multi-ext.example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractTLSSNI(tc.payload)
			if got != tc.want {
				t.Errorf("extractTLSSNI() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ─── DNS query extraction ─────────────────────────────────────────────────────

// buildDNSQueryPacket serialises a full Ethernet/IP/UDP/DNS stack containing
// a single A-record question for questionName.
func buildDNSQueryPacket(questionName string) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("192.168.1.1").To4(),
		DstIP:    net.ParseIP("8.8.8.8").To4(),
	}
	udp := &layers.UDP{SrcPort: 54321, DstPort: 53}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err)
	}
	dns := &layers.DNS{
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(questionName),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns); err != nil {
		panic(err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// buildDNSResponsePacket creates a DNS response (QR=true) which should be ignored.
func buildDNSResponsePacket(questionName string) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("8.8.8.8").To4(),
		DstIP:    net.ParseIP("192.168.1.1").To4(),
	}
	udp := &layers.UDP{SrcPort: 53, DstPort: 54321}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err)
	}
	dns := &layers.DNS{
		QR: true, // this is a response
		Questions: []layers.DNSQuestion{
			{Name: []byte(questionName), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns); err != nil {
		panic(err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestExtractDNSQuery(t *testing.T) {
	tests := []struct {
		name   string
		pkt    gopacket.Packet
		want   string
	}{
		{
			name: "standard A query",
			pkt:  buildDNSQueryPacket("example.com"),
			want: "example.com",
		},
		{
			name: "subdomain query",
			pkt:  buildDNSQueryPacket("api.internal.corp"),
			want: "api.internal.corp",
		},
		{
			name: "response packet is ignored",
			pkt:  buildDNSResponsePacket("example.com"),
			want: "",
		},
		{
			name: "no DNS layer (TCP packet)",
			pkt:  buildIPv4TCPPacket(t, "10.0.0.1", "10.0.0.2", 12345, 80, nil),
			want: "",
		},
		{
			name: "DNS query with zero questions",
			pkt: func() gopacket.Packet {
				eth := &layers.Ethernet{
					SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
					DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
					EthernetType: layers.EthernetTypeIPv4,
				}
				ip := &layers.IPv4{
					Version:  4,
					TTL:      64,
					Protocol: layers.IPProtocolUDP,
					SrcIP:    net.ParseIP("192.168.1.1").To4(),
					DstIP:    net.ParseIP("8.8.8.8").To4(),
				}
				udp := &layers.UDP{SrcPort: 54321, DstPort: 53}
				if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
					panic(err)
				}
				dns := &layers.DNS{Questions: nil} // zero questions
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
				if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns); err != nil {
					panic(err)
				}
				return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
			}(),
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractDNSQuery(tc.pkt)
			if got != tc.want {
				t.Errorf("extractDNSQuery() = %q, want %q", got, tc.want)
			}
		})
	}
}

// ─── packet builders ──────────────────────────────────────────────────────────

func buildIPv4TCPPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort)}
	if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	var serr error
	if len(payload) > 0 {
		serr = gopacket.SerializeLayers(buf, opts, eth, ip4, tcp, gopacket.Payload(payload))
	} else {
		serr = gopacket.SerializeLayers(buf, opts, eth, ip4, tcp)
	}
	if serr != nil {
		t.Fatalf("SerializeLayers: %v", serr)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func buildIPv4UDPPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, udp); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func buildIPv6TCPPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      net.ParseIP(srcIP),
		DstIP:      net.ParseIP(dstIP),
	}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort)}
	if err := tcp.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, tcp); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func buildIPv4ICMPPacket(t *testing.T, srcIP, dstIP string) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0)}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, icmp); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// writePcapFile writes a minimal valid pcap v2.4 file (little-endian, Ethernet link type)
// containing the given raw packet byte slices. Returns the file path.
func writePcapFile(t *testing.T, packets [][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "capture.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	defer f.Close()

	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatalf("write pcap: %v", e)
		}
	}
	// Global header — little-endian native pcap v2.4, Ethernet (DLT_EN10MB = 1).
	must(binary.Write(f, binary.LittleEndian, uint32(0xa1b2c3d4))) // magic
	must(binary.Write(f, binary.LittleEndian, uint16(2)))          // version major
	must(binary.Write(f, binary.LittleEndian, uint16(4)))          // version minor
	must(binary.Write(f, binary.LittleEndian, int32(0)))           // GMT offset
	must(binary.Write(f, binary.LittleEndian, uint32(0)))          // timestamp accuracy
	must(binary.Write(f, binary.LittleEndian, uint32(65535)))      // snaplen
	must(binary.Write(f, binary.LittleEndian, uint32(1)))          // Ethernet

	for _, pkt := range packets {
		must(binary.Write(f, binary.LittleEndian, uint32(0)))        // ts_sec
		must(binary.Write(f, binary.LittleEndian, uint32(0)))        // ts_usec
		must(binary.Write(f, binary.LittleEndian, uint32(len(pkt)))) // incl_len
		must(binary.Write(f, binary.LittleEndian, uint32(len(pkt)))) // orig_len
		if _, werr := f.Write(pkt); werr != nil {
			t.Fatalf("write pcap packet: %v", werr)
		}
	}
	return path
}

// ─── parsePacket ─────────────────────────────────────────────────────────────

func TestParsePacket_Nil(t *testing.T) {
	if parsePacket(nil) != nil {
		t.Error("expected nil for nil input")
	}
}

func TestParsePacket_IPv4TCP_NoPayload(t *testing.T) {
	pkt := buildIPv4TCPPacket(t, "10.0.0.1", "10.0.0.2", 12345, 80, nil)
	ev := parsePacket(pkt)
	if ev == nil {
		t.Fatal("expected non-nil event")
	}
	if ev.Proto != "TCP" {
		t.Errorf("Proto = %q, want TCP", ev.Proto)
	}
	if ev.SrcPort != 12345 {
		t.Errorf("SrcPort = %d, want 12345", ev.SrcPort)
	}
	if ev.DstPort != 80 {
		t.Errorf("DstPort = %d, want 80", ev.DstPort)
	}
	if ev.TLSSNIName != "" {
		t.Errorf("expected empty TLSSNIName, got %q", ev.TLSSNIName)
	}
	if ev.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestParsePacket_IPv4TCP_TLSPayload(t *testing.T) {
	tls := buildClientHello("secure.example.com")
	pkt := buildIPv4TCPPacket(t, "10.0.0.1", "10.0.0.2", 55000, 443, tls)
	ev := parsePacket(pkt)
	if ev == nil {
		t.Fatal("expected non-nil event")
	}
	if ev.TLSSNIName != "secure.example.com" {
		t.Errorf("TLSSNIName = %q, want %q", ev.TLSSNIName, "secure.example.com")
	}
}

func TestParsePacket_IPv4UDP_DNS(t *testing.T) {
	pkt := buildDNSQueryPacket("lookup.example.com")
	ev := parsePacket(pkt)
	if ev == nil {
		t.Fatal("expected non-nil event")
	}
	if ev.Proto != "UDP" {
		t.Errorf("Proto = %q, want UDP", ev.Proto)
	}
	if ev.DNSQuery != "lookup.example.com" {
		t.Errorf("DNSQuery = %q, want %q", ev.DNSQuery, "lookup.example.com")
	}
}

func TestParsePacket_IPv4UDP_NonDNS(t *testing.T) {
	pkt := buildIPv4UDPPacket(t, "10.0.0.1", "10.0.0.2", 12345, 9999)
	ev := parsePacket(pkt)
	if ev == nil {
		t.Fatal("expected non-nil event")
	}
	if ev.DNSQuery != "" {
		t.Errorf("expected empty DNSQuery for non-DNS port, got %q", ev.DNSQuery)
	}
}

func TestParsePacket_IPv6TCP(t *testing.T) {
	pkt := buildIPv6TCPPacket(t, "2001:db8::1", "2001:db8::2", 54321, 443)
	ev := parsePacket(pkt)
	if ev == nil {
		t.Fatal("expected non-nil event for IPv6/TCP")
	}
	if ev.Proto != "TCP" {
		t.Errorf("Proto = %q, want TCP", ev.Proto)
	}
}

func TestParsePacket_NoNetworkLayer_ReturnsNil(t *testing.T) {
	// All-zero Ethernet frame: EtherType 0x0000 is unknown to gopacket → no network layer.
	pkt := gopacket.NewPacket(make([]byte, 64), layers.LayerTypeEthernet, gopacket.Default)
	if parsePacket(pkt) != nil {
		t.Error("expected nil for packet with unknown EtherType")
	}
}

func TestParsePacket_NoTransportLayer_ReturnsNil(t *testing.T) {
	// IPv4/ICMP: ICMPv4 does not implement gopacket.TransportLayer.
	pkt := buildIPv4ICMPPacket(t, "10.0.0.1", "10.0.0.2")
	if parsePacket(pkt) != nil {
		t.Error("expected nil for IPv4/ICMP (no transport layer)")
	}
}

// ─── buildIPFlagsMap ─────────────────────────────────────────────────────────

func TestBuildIPFlagsMap_ReturnsNonNilMap(t *testing.T) {
	m := buildIPFlagsMap()
	if m == nil {
		t.Fatal("buildIPFlagsMap returned nil")
	}
	for ip := range m {
		if ip == "" {
			t.Error("empty IP key found in flags map")
		}
	}
}

// ─── OfflineReader ────────────────────────────────────────────────────────────

func TestOfflineReader_Read_ValidPacket(t *testing.T) {
	rawPkt := buildIPv4TCPPacket(t, "10.0.0.1", "10.0.0.2", 12345, 80, nil).Data()
	path := writePcapFile(t, [][]byte{rawPkt})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := OfflineReader{FilePath: path}.Read(ctx)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}

	var events []PacketEvent
	for e := range ch {
		events = append(events, e)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Proto != "TCP" || events[0].DstPort != 80 {
		t.Errorf("unexpected event: %+v", events[0])
	}
}

func TestOfflineReader_Read_EmptyFile_ClosesChannel(t *testing.T) {
	path := writePcapFile(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := OfflineReader{FilePath: path}.Read(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := 0
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 events from empty pcap, got %d", count)
	}
}

func TestOfflineReader_Read_NonExistentFile_ReturnsError(t *testing.T) {
	_, err := OfflineReader{FilePath: "/no/such/file.pcap"}.Read(context.Background())
	if err == nil {
		t.Error("expected error for non-existent pcap file")
	}
}

func TestOfflineReader_Read_InvalidBPFFilter_ReturnsError(t *testing.T) {
	path := writePcapFile(t, nil)
	_, err := OfflineReader{FilePath: path, BPFFilter: "invalid bpf !!!SYNTAX@@@"}.Read(context.Background())
	if err == nil {
		t.Error("expected error for invalid BPF filter")
	}
}

func TestOfflineReader_Read_GarbagePacket_Skipped(t *testing.T) {
	// All-zero 64-byte payload: Ethernet with EtherType=0x0000 → parsePacket returns nil.
	path := writePcapFile(t, [][]byte{make([]byte, 64)})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ch, err := OfflineReader{FilePath: path}.Read(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := 0
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 events (garbage skipped), got %d", count)
	}
}

func TestOfflineReader_Read_ContextCancel_ClosesChannel(t *testing.T) {
	rawPkt := buildIPv4TCPPacket(t, "10.0.0.1", "10.0.0.2", 1111, 2222, nil).Data()
	packets := make([][]byte, 500)
	for i := range packets {
		packets[i] = rawPkt
	}
	path := writePcapFile(t, packets)

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := OfflineReader{FilePath: path}.Read(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	<-ch   // receive at least one event
	cancel() // cancel before draining all 500
	for range ch {
	} // must close cleanly
}

// TestOfflineReader_Read_PreCancelledContext exercises the top-of-loop
// ctx.Done() check in drainPackets: when the context is already cancelled
// before any packet is processed, the goroutine may exit on the first iteration.
func TestOfflineReader_Read_PreCancelledContext(t *testing.T) {
	rawPkt := buildIPv4TCPPacket(t, "10.0.0.1", "10.0.0.2", 5000, 80, nil).Data()
	path := writePcapFile(t, [][]byte{rawPkt, rawPkt, rawPkt})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel BEFORE Read — drainPackets sees ctx.Done at top of first loop

	ch, err := OfflineReader{FilePath: path}.Read(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Drain channel — may get 0 or a few events depending on goroutine scheduling.
	count := 0
	for range ch {
		count++
	}
	t.Logf("events received with pre-cancelled context: %d", count)
}

// TestOfflineReader_Read_BufferFull_CtxDoneExits fills the 4096-packet channel
// buffer, then cancels the context so drainPackets exits via the send-select
// case <-ctx.Done(): return path (capture.go:88-89).
func TestOfflineReader_Read_BufferFull_CtxDoneExits(t *testing.T) {
	rawPkt := buildIPv4TCPPacket(t, "10.0.0.1", "10.0.0.2", 6000, 443, nil).Data()
	// More packets than the 4096-entry channel buffer so the goroutine blocks.
	const n = 5000
	packets := make([][]byte, n)
	for i := range packets {
		packets[i] = rawPkt
	}
	path := writePcapFile(t, packets)

	ctx, cancel := context.WithCancel(context.Background())

	ch, err := OfflineReader{FilePath: path}.Read(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Spin until the goroutine has filled the channel buffer (cap=4096).
	// At that point the goroutine is blocked inside the send select, so
	// cancel() will fire the ctx.Done case deterministically.
	deadline := time.Now().Add(10 * time.Second)
	for len(ch) < cap(ch) {
		if time.Now().After(deadline) {
			cancel()
			for range ch {
			}
			t.Skip("buffer did not fill within deadline — skipping send-select coverage")
			return
		}
		runtime.Gosched()
	}

	cancel()
	for range ch {
	}
}
