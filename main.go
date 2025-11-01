package main

import (
	"flag"
	"log"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	iface   = flag.String("iface", "", "Npcap interface name (kosongkan untuk auto-pick)")
	snaplen = flag.Int("snaplen", 96, "SnapLen bytes per packet")
	promisc = flag.Bool("promisc", true, "Promiscuous mode")
	timeout = flag.Duration("timeout", pcap.BlockForever, "pcap timeout (BlockForever disarankan)")
	// Filter: TCP SYN (tanpa ACK) untuk ip & ip6
	// Catatan: tcp[13] & 0x02 != 0  => SYN bit set
	//          tcp[13] & 0x10 == 0  => ACK bit tidak set
	bpf = flag.String("bpf", "(ip or ip6) and tcp and (tcp[13] & 0x02 != 0) and (tcp[13] & 0x10 == 0)", "BPF filter")
)

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	dev := *iface
	if dev == "" {
		// Auto-pick interface pertama yang up & punya alamat
		devs, err := pcap.FindAllDevs()
		if err != nil || len(devs) == 0 {
			log.Fatalf("Tidak menemukan interface Npcap: %v", err)
		}
		for _, d := range devs {
			if len(d.Addresses) > 0 {
				dev = d.Name
				break
			}
		}
		if dev == "" {
			log.Fatalf("Tidak ada interface yang valid, gunakan -iface untuk memilih.")
		}
	}

	handle, err := pcap.OpenLive(dev, int32(*snaplen), *promisc, *timeout)
	if err != nil {
		log.Fatalf("OpenLive gagal di %s: %v", dev, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(*bpf); err != nil {
		log.Fatalf("SetBPFFilter gagal: %v", err)
	}
	log.Printf("[*] Sniffing on: %s", dev)
	log.Printf("[*] BPF: %s", *bpf)

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range src.Packets() {
		printSYN(pkt)
	}
}

func printSYN(pkt gopacket.Packet) {
	net := pkt.NetworkLayer()
	tr := pkt.TransportLayer()

	if net == nil || tr == nil {
		return
	}
	tcp, _ := tr.(*layers.TCP)
	if tcp == nil {
		return
	}

	// Extra guard (selain BPF) kalau-kalau filter diubah
	if !(tcp.SYN && !tcp.ACK) {
		return
	}

	srcIP := net.NetworkFlow().Src().String()
	dstIP := net.NetworkFlow().Dst().String()
	// ringkas info flags
	flags := []string{}
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}

	log.Printf("[SYN] %s:%d -> %s:%d flags=%s win=%d ts=%s",
		srcIP, tcp.SrcPort, dstIP, tcp.DstPort, strings.Join(flags, "|"),
		tcp.Window, time.Now().Format(time.RFC3339Nano))
}
