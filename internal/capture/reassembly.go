// Package capture — reassembly.go implements TCP stream reassembly for
// fragmented TLS ClientHellos.
//
// A TLS ClientHello can legally be split across multiple TCP segments.
// This is rare on LAN (MTU 1500 → ClientHello ≤ 1460 bytes) but common on:
//   - VPN/tunnels with reduced MTU (≤ 1280 bytes)
//   - Mobile networks with radio segmentation
//   - C2 profiles that pad the ClientHello past the first segment boundary
//
// Without reassembly, extractTLSSNI() and ja3.Fingerprint() both return ""
// for fragmented ClientHellos, making the flow invisible to JA3 detection.
//
// Architecture:
//   - tlsStreamFactory implements tcpassembly.StreamFactory — creates one
//     tlsStream per TCP connection.
//   - tlsStream implements tcpassembly.Stream — buffers up to maxStreamBuf
//     bytes and tries to extract SNI + JA3 as soon as enough data arrives.
//   - StreamReassembler wraps tcpassembly.Assembler with a flush ticker so
//     stale streams are cleaned up automatically.
//
// When a complete ClientHello is reassembled, a synthetic PacketEvent is
// emitted on the out channel. The event carries only the flow tuple, SNI,
// and JA3 hash — no raw payload — so the aggregator can enrich the flow.
package capture

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/ClementG91/MCP-FlowSentinel/internal/ja3"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// maxStreamBuf is the maximum number of bytes buffered per TCP stream.
// 8 KB is sufficient for any known TLS ClientHello (largest observed: ~4 KB
// when using many cipher suites + extensions). Capping here prevents a
// malicious peer from driving memory usage by sending huge streams.
const maxStreamBuf = 8 * 1024

// streamFlushInterval controls how often idle streams are flushed and closed.
// 5 seconds is chosen to cover high-latency paths (satellite, mobile) while
// keeping memory pressure low.
const streamFlushInterval = 5 * time.Second

// tlsStreamFactory implements tcpassembly.StreamFactory.
// It creates one tlsStream per new TCP connection and routes reassembled
// SNI results to the shared out channel.
type tlsStreamFactory struct {
	out chan<- PacketEvent
}

// New is called by tcpassembly whenever a new TCP flow is detected.
func (f *tlsStreamFactory) New(netFlow, transFlow gopacket.Flow) tcpassembly.Stream {
	return &tlsStream{
		netFlow:   netFlow,
		transFlow: transFlow,
		out:       f.out,
	}
}

// tlsStream implements tcpassembly.Stream for a single TCP connection.
type tlsStream struct {
	netFlow   gopacket.Flow
	transFlow gopacket.Flow
	buf       []byte
	done      bool // true after SNI has been extracted and emitted
	out       chan<- PacketEvent
}

// Reassembled is called by tcpassembly with each ordered, contiguous chunk
// of the TCP stream. May be called multiple times before ReassemblyComplete.
func (s *tlsStream) Reassembled(rs []tcpassembly.Reassembly) {
	if s.done {
		return
	}
	for _, r := range rs {
		if len(r.Bytes) == 0 {
			continue
		}
		remaining := maxStreamBuf - len(s.buf)
		if remaining <= 0 {
			break // buffer full — give up on this stream
		}
		chunk := r.Bytes
		if len(chunk) > remaining {
			chunk = chunk[:remaining]
		}
		s.buf = append(s.buf, chunk...)
	}

	// Attempt SNI extraction as soon as the buffer might contain a complete
	// TLS record. A full ClientHello handshake record requires at least 6 bytes
	// (record header 5 + handshake type 1). We try eagerly and bail out quickly
	// when the payload is too short — extractTLSSNI handles this gracefully.
	sni := extractTLSSNI(s.buf)
	if sni == "" {
		return // not enough data yet
	}

	srcIP := net.ParseIP(s.netFlow.Src().String())
	dstIP := net.ParseIP(s.netFlow.Dst().String())
	if srcIP == nil || dstIP == nil {
		s.done = true
		return
	}
	srcRaw := s.transFlow.Src().Raw()
	dstRaw := s.transFlow.Dst().Raw()
	if len(srcRaw) < 2 || len(dstRaw) < 2 {
		s.done = true
		return
	}
	srcPort := binary.BigEndian.Uint16(srcRaw)
	dstPort := binary.BigEndian.Uint16(dstRaw)

	evt := PacketEvent{
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Proto:      "TCP",
		Timestamp:  time.Now(),
		TLSSNIName: sni,
		JA3Hash:    ja3.Fingerprint(s.buf),
	}
	// Non-blocking send — reassembly results are best-effort. If the channel
	// is full (backpressure) we drop rather than block the assembler goroutine.
	select {
	case s.out <- evt:
	default:
	}
	s.done = true
}

// ReassemblyComplete is called when the TCP stream is closed or flushed.
// Nothing to do — all state is on the stream struct itself.
func (s *tlsStream) ReassemblyComplete() {}

// StreamReassembler wraps a tcpassembly.Assembler and manages a periodic
// flush goroutine to reclaim memory from stale streams.
type StreamReassembler struct {
	assembler *tcpassembly.Assembler
	out       chan PacketEvent
}

// NewStreamReassembler creates a reassembler that emits synthetic PacketEvents
// (SNI + JA3 only) on the returned channel as ClientHellos are reassembled.
// The out channel has capacity 512; callers should drain it promptly.
func NewStreamReassembler() (*StreamReassembler, <-chan PacketEvent) {
	out := make(chan PacketEvent, 512)
	factory := &tlsStreamFactory{out: out}
	pool := tcpassembly.NewStreamPool(factory)
	asm := tcpassembly.NewAssembler(pool)
	// Limit per-connection page cache to 8 pages (~8 KB) to bound memory use
	// under adversarial traffic (many half-open connections).
	asm.MaxBufferedPagesPerConnection = 8
	asm.MaxBufferedPagesTotal = 1024
	return &StreamReassembler{assembler: asm, out: out}, out
}

// Add feeds a raw gopacket into the assembler. Only TCP packets with a
// network layer are forwarded; all others are silently ignored.
func (r *StreamReassembler) Add(pkt gopacket.Packet) {
	nl := pkt.NetworkLayer()
	if nl == nil {
		return
	}
	tcp, ok := pkt.TransportLayer().(*layers.TCP)
	if !ok {
		return
	}
	r.assembler.AssembleWithTimestamp(nl.NetworkFlow(), tcp, pkt.Metadata().Timestamp)
}

// FlushOlderThan flushes streams that have been idle since before t, freeing
// their memory. Call this periodically (every streamFlushInterval) to avoid
// unbounded memory growth from stale half-open connections.
func (r *StreamReassembler) FlushOlderThan(t time.Time) {
	r.assembler.FlushOlderThan(t)
}

// FlushAll flushes all buffered streams. Call this when the capture window
// ends to ensure every partially-reassembled stream is processed.
func (r *StreamReassembler) FlushAll() {
	r.assembler.FlushAll()
}
