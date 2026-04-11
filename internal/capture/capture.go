package capture

import (
	"context"
	"fmt"
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
	go func() {
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
				// pcap read-timeout or EOF; check context and keep going.
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
	}()

	return ch, nil
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

	switch tl := transLayer.(type) {
	case *layers.TCP:
		srcPort = uint16(tl.SrcPort)
		dstPort = uint16(tl.DstPort)
		proto = "TCP"
		payloadLen = uint32(len(tl.Payload))
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

	return &PacketEvent{
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Proto:      proto,
		PayloadLen: payloadLen,
		Timestamp:  ts,
	}
}
