package capture

import (
	"context"
	"fmt"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// PacketReader is the common abstraction for live and offline pcap sources.
// Implementations stream PacketEvents on the returned channel until the source
// is exhausted or ctx is cancelled, then close the channel.
type PacketReader interface {
	Read(ctx context.Context) (<-chan PacketEvent, error)
}

// LiveReader captures packets in real-time from a named network interface.
type LiveReader struct {
	Iface     string
	BPFFilter string
}

// Read implements PacketReader for live capture.
func (r LiveReader) Read(ctx context.Context) (<-chan PacketEvent, error) {
	return CapturePackets(ctx, r.Iface, r.BPFFilter)
}

// OfflineReader replays packets from an existing pcap / pcapng file.
type OfflineReader struct {
	FilePath  string
	BPFFilter string
}

// Read implements PacketReader for offline pcap files.
// The channel is closed when the file is fully read or ctx is cancelled.
// Unlike LiveReader there is no wall-clock timeout — the file is read as fast
// as the OS allows.
func (r OfflineReader) Read(ctx context.Context) (<-chan PacketEvent, error) {
	handle, err := pcap.OpenOffline(r.FilePath)
	if err != nil {
		return nil, fmt.Errorf("pcap OpenOffline(%s): %w", r.FilePath, err)
	}

	if r.BPFFilter != "" {
		if err := handle.SetBPFFilter(r.BPFFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("BPF filter %q: %w", r.BPFFilter, err)
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
			if err == io.EOF {
				return // file fully consumed
			}
			if err != nil {
				continue // skip malformed packets
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
