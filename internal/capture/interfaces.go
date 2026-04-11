// Package capture handles low-level packet capture and NIC enumeration.
package capture

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

// Interface describes a network interface visible to pcap.
//
// Cross-platform note:
//   - Name is the pcap device identifier — pass it directly to analyze_network.
//     Linux/macOS: "eth0", "en0", "lo" …
//     Windows    : "\Device\NPF_{GUID}" (shown alongside Description)
//   - Description is the human-readable label. Always present on Windows;
//     may be empty on Linux/macOS.
type Interface struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Addresses   []string `json:"addresses"`
	Flags       []string `json:"flags"`
}

// ListInterfaces returns all pcap-visible network interfaces.
// Name is always the correct identifier for pcap.OpenLive / analyze_network.
// On Windows, pcap device names ("\Device\NPF_{...}") differ from OS names
// ("Ethernet") — this function resolves that automatically.
func ListInterfaces() ([]Interface, error) {
	pcapDevs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("pcap FindAllDevs: %w", err)
	}

	// Build IP → flags lookup from the OS network stack for flag enrichment.
	ipFlags := buildIPFlagsMap()

	result := make([]Interface, 0, len(pcapDevs))
	for _, dev := range pcapDevs {
		var addrs []string
		flagSet := make(map[string]struct{})

		for _, a := range dev.Addresses {
			if a.IP == nil {
				continue
			}
			ones, _ := a.Netmask.Size()
			addrs = append(addrs, fmt.Sprintf("%s/%d", a.IP, ones))

			// Inherit OS-level flags via IP matching (works across all platforms).
			if flist, ok := ipFlags[a.IP.String()]; ok {
				for _, f := range flist {
					flagSet[f] = struct{}{}
				}
			}
		}

		flags := make([]string, 0, len(flagSet))
		for f := range flagSet {
			flags = append(flags, f)
		}

		result = append(result, Interface{
			Name:        dev.Name,
			Description: dev.Description,
			Addresses:   addrs,
			Flags:       flags,
		})
	}
	return result, nil
}

// buildIPFlagsMap returns a map from IP address string → OS interface flags.
func buildIPFlagsMap() map[string][]string {
	result := make(map[string][]string)
	sysIfaces, err := net.Interfaces()
	if err != nil {
		return result
	}

	for _, iface := range sysIfaces {
		var flags []string
		if iface.Flags&net.FlagUp != 0 {
			flags = append(flags, "up")
		}
		if iface.Flags&net.FlagLoopback != 0 {
			flags = append(flags, "loopback")
		}
		if iface.Flags&net.FlagMulticast != 0 {
			flags = append(flags, "multicast")
		}
		if iface.Flags&net.FlagPointToPoint != 0 {
			flags = append(flags, "p2p")
		}

		ifAddrs, _ := iface.Addrs()
		for _, a := range ifAddrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil {
				result[ip.String()] = flags
			}
		}
	}
	return result
}
