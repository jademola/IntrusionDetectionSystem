// 1. Package Declaration
package main

// 2. Imports (The tools we are borrowing)
import (
	"fmt" //printing to console
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers" //To read IP layers
	"github.com/google/gopacket/pcap"
)

// 3. The Main Function (The entry point)
func main() {
	fmt.Println("GoGuard IPS: Defender Node is starting...")
	fmt.Println("Interface: enp0s8 (Target)")

	device := "enp0s8"
	fmt.Printf("GoGuard IPS: Monitoring %s...\n", device)

	//open device for packet sniffing (local host network, packetsize, promiscuous mode, )
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)

	//checks if Openlive fail - Like if you forget sudo
	if err != nil {
		log.Fatal(err)
	}

	//closes network connection to prevent memory leak
	defer handle.Close()

	// Use the handle as a packet source - translates binary into readable packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	//Loop through packets
	for packet := range packetSource.Packets() {
		//Look for the IP layer in this packet
		ipLayer := packet.Layer(layers.LayerTypeIPv4)

		//Convert generic ipLayer into IPv4 object to read the source, destination and protocol
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			fmt.Printf("Detection: [%s] --> [%s] | Protocol: %s\n", ip.SrcIP, ip.DstIP, ip.Protocol)

		}

	}

}
