package capture

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
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
	// libpcap is still used when a BPF expression must be compiled. The common
	// no-filter path uses pcapgo, so offline analysis works without Npcap/libpcap.
	if r.BPFFilter != "" {
		return r.readWithLibpcap(ctx)
	}

	f, err := os.Open(r.FilePath)
	if err != nil {
		return nil, fmt.Errorf("open capture %s: %w", r.FilePath, err)
	}
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("read capture header %s: %w", r.FilePath, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("seek capture %s: %w", r.FilePath, err)
	}

	var src *gopacket.PacketSource
	if bytes.Equal(magic[:], []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		reader, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("open pcapng %s: %w", r.FilePath, err)
		}
		src = gopacket.NewPacketSource(reader, reader.LinkType())
	} else {
		reader, err := pcapgo.NewReader(f)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("open pcap %s: %w", r.FilePath, err)
		}
		src = gopacket.NewPacketSource(reader, reader.LinkType())
	}
	src.NoCopy = true
	ch := make(chan PacketEvent, 4096)
	go drainPacketSource(ctx, src, ch, true, func() { _ = f.Close() }, nil)
	return ch, nil
}

func (r OfflineReader) readWithLibpcap(ctx context.Context) (<-chan PacketEvent, error) {
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
	go drainPackets(ctx, handle, ch, true)
	return ch, nil
}
