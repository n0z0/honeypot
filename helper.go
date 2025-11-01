package main

import (
	"log"
	"strings"

	"github.com/google/gopacket/pcap"
)

// --- helpers ---

func loadLocalIPsFor(devName string) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Printf("[WARN] FindAllDevs error: %v", err)
	}
	for _, d := range devs {
		if d.Name == devName {
			for _, a := range d.Addresses {
				if a.IP != nil {
					localIPs[stripZone(a.IP.String())] = struct{}{}
				}
			}
			break
		}
	}
	// jaga-jaga
	localIPs["127.0.0.1"] = struct{}{}
	localIPs["::1"] = struct{}{}
}

func stripZone(ip string) string {
	// buang zone-id IPv6, contoh: fe80::1234%12 -> fe80::1234
	if i := strings.IndexByte(ip, '%'); i >= 0 {
		return ip[:i]
	}
	return ip
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
