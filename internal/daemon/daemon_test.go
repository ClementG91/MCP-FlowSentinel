package daemon

import (
	"testing"

	"github.com/ClementG91/MCP-FlowSentinel/internal/capture"
)

func iface(name string, flags []string, addrs []string) capture.Interface {
	return capture.Interface{Name: name, Flags: flags, Addresses: addrs}
}

func TestSelectInterface_NonLoopbackWithAddr_Preferred(t *testing.T) {
	ifaces := []capture.Interface{
		iface("lo", []string{"loopback", "up"}, []string{"127.0.0.1/8"}),
		iface("eth0", []string{"up", "multicast"}, []string{"192.168.1.10/24"}),
		iface("eth1", []string{"up"}, []string{"10.0.0.2/24"}),
	}
	got := selectInterface(ifaces)
	if got != "eth0" {
		t.Errorf("selectInterface = %q, want eth0", got)
	}
}

func TestSelectInterface_LoopbackOnly_ReturnsEmpty(t *testing.T) {
	ifaces := []capture.Interface{
		iface("lo", []string{"loopback", "up"}, []string{"127.0.0.1/8"}),
	}
	got := selectInterface(ifaces)
	if got != "" {
		t.Errorf("selectInterface with loopback-only = %q, want empty", got)
	}
}

func TestSelectInterface_EmptyList_ReturnsEmpty(t *testing.T) {
	got := selectInterface(nil)
	if got != "" {
		t.Errorf("selectInterface(nil) = %q, want empty", got)
	}
}

func TestSelectInterface_NoAddresses_FallsBack(t *testing.T) {
	ifaces := []capture.Interface{
		iface("lo", []string{"loopback"}, []string{"127.0.0.1/8"}),
		iface("eth0", []string{"up"}, nil), // no addresses
	}
	got := selectInterface(ifaces)
	if got != "eth0" {
		t.Errorf("selectInterface with no-addr fallback = %q, want eth0", got)
	}
}

func TestSelectInterface_SkipsLoopbackEvenWithAddr(t *testing.T) {
	ifaces := []capture.Interface{
		iface("lo", []string{"loopback", "up"}, []string{"127.0.0.1/8"}),
		iface("wlan0", []string{"up"}, []string{"192.168.0.5/24"}),
	}
	got := selectInterface(ifaces)
	if got != "wlan0" {
		t.Errorf("selectInterface = %q, want wlan0", got)
	}
}

func TestHasFlag_Found(t *testing.T) {
	if !hasFlag([]string{"up", "loopback", "multicast"}, "loopback") {
		t.Error("hasFlag should find loopback")
	}
}

func TestHasFlag_NotFound(t *testing.T) {
	if hasFlag([]string{"up", "multicast"}, "loopback") {
		t.Error("hasFlag should not find loopback")
	}
}

func TestHasFlag_EmptySlice(t *testing.T) {
	if hasFlag(nil, "loopback") {
		t.Error("hasFlag(nil) should return false")
	}
}
