// 1. Package Declaration
package main

// 2. Imports (The tools we are borrowing)
import (
	"fmt" //printing to console
	"log"
	"time"
	// for logging
	"os"
	"bufio"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers" //To read IP layers
	"github.com/google/gopacket/pcap"
)

// applyFilters sets the BPF rules to ignore SSH noise
func applyFilters(handle *pcap.Handle) {
	// Standard SSH is 22; VirtualBox often uses 2222 for port forwarding
	filter := "not port 22 and not port 2222 and not dst host 192.168.56.255 and not host 192.168.56.100"
	err := handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Error applying BPF filter: %v", err)
	}
	fmt.Println("Network filters active: Ignoring SSH management traffic and Broadcast Noise.")
}

// 3. The Main Function (The entry point)
func main() {
	fmt.Println("GoGuard IPS: Defender Node is starting...")
	fmt.Println("Interface: enp0s8 (Target)")

	device := "enp0s8"
	snapshotLen := int32(1024)
	promiscuous := false
	timeout := 30 * time.Second

	//open device for packet sniffing (local host network, packetsize, promiscuous mode, )
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)

	//checks if Openlive fail - i.e., if you forget sudo
	if err != nil {
		log.Fatal(err)
	}

	//closes network connection to prevent memory leak
	defer handle.Close()

	//Filter out SSH traffic and VirtualBox
	applyFilters(handle)

	fmt.Printf("GoGuard: Monitoring %s. Waiting for packets...\n", device)
	fmt.Println("---------------------------------------------------------")

	// Use the handle as a packet source - translates binary into readable packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	//Loop through packets
	for packet := range packetSource.Packets() {
		//Look for the IP layer in this packet
		ipLayer := packet.Layer(layers.LayerTypeIPv4)

		//Convert generic ipLayer into IPv4 object to read the source, destination and protocol
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			// Get a human-readable timestamp
			timestamp := time.Now().Format("15:04:05")
			dateTime := now.Format("2006-01-02 15:04:05")

			// The "Detection" Output
			fmt.Printf("[%s] Detection: %s --> %s | Proto: %s\n",
				timestamp,
				ip.SrcIP,
				ip.DstIP,
				ip.Protocol,
			)

			logPacketInfo := fmt.Sprintf("[%s] Detection: %s --> %s | Proto: %s\n",
				timestamp,
				ip.SrcIP,
				ip.DstIP,
				ip.Protocol,
			)
		
			log := fmt.Sprintf("logs/log_%s", dateTime)

			err := os.writeFile(log, []byte(logPacketInfo), 0644
			if err != nil {
				panic(err)
			}


		}

	}

}
