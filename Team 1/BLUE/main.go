// 1. Package Declaration
package main

// 2. Imports (The tools we are borrowing)
import (
	"fmt" //printing to console
	"log"
	"strings"
	"time"

	// for logging
	"os"
	// for nmap counts
	"sync"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers" //To read IP layers
	"github.com/google/gopacket/pcap"
)

var totalPackets uint64
var perIP sync.Map // map[string]*uint64
var blacklist sync.Map

// Dangerous keywords used in packet inspection
var dangerZone = []string{
	"SELECT", "DROP", "UNION", "INSERT", // SQL Injection
	"<script>", "alert(", // XSS
	"/etc/passwd", "/etc/shadow", //Linux System File Access
	"admin", "password", "login", // Credential Hunting
}

// applyFilters sets the BPF rules to ignore SSH noise
func applyFilters(handle *pcap.Handle) {
	// 1. "not port 22 and not port 2222" -> Ignores SSH
	// 2. "not host 192.168.56.1" -> Ignores all traffic FROM or TO your Windows/Mac host
	// 3. "not net 224.0.0.0/4" -> Ignores ALL Multicast traffic (SSDP, mDNS, etc.)
	filter := "not port 22 and not port 2222 and not host 192.168.56.1 and not net 224.0.0.0/4"

	err := handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Error applying BPF filter: %v", err)
	}
	fmt.Println("Network filters active: SSH, Host Noise, and Multicast ignored.")
}

func inspectPayload(src string, data []byte, logFile *os.File) {
	//Convert binary payload to string for searching
	payload := string(data)
	upperPayload := strings.ToUpper(payload)

	for _, keyword := range dangerZone {
		if strings.Contains(upperPayload, strings.ToUpper(keyword)) {
			timestamp := time.Now().Format("15:04:05.999999")
			alertMsg := fmt.Sprintf("[%s] !!! DPI ALERT: Keyword '%s' detected from %s\n", timestamp, keyword, src)

			//Print alert
			fmt.Print(alertMsg)

			//Create alert and send it to dashboard
			payloadAlert := Alert{
				Timestamp: time.Now().Format("15:04:05"),
				Source:    src,
				Message:   fmt.Sprintf("Keyword '%s' detected", keyword),
				Type:      "DPI",
			}
			broadcast <- payloadAlert

			// Write to main log
			if logFile != nil {
				logFile.WriteString(alertMsg)
			}

			//Exit on first detection
			break
		}
	}

}

func detectFlooding() {
	// Make flag directory if not present
	_ = os.MkdirAll("flags", 0755)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	dateTime := time.Now().Format("2006-01-02_15-04-05")
	logName := fmt.Sprintf("flags/log_%s", dateTime)

	for range ticker.C {
		totalRate := atomic.SwapUint64(&totalPackets, 0)
		logHighRate, logIP := "", ""

		if totalRate > 5000 {
			logHighRate = fmt.Sprintf("!!! High Total Rate Detected: %d packets/per sec\n", totalRate)
		}

		perIP.Range(func(key, value any) bool {
			ip := key.(string)
			count := atomic.SwapUint64(value.(*uint64), 0)

			// test for nmap resulted in 1700+ packets sent and received
			if count > 500 {
				logIP += fmt.Sprintf("!!! Possible packet flooding from %s: %d packets/per sec\n", ip, count)

				//Create alert and send it to dashboard
				floodAlert := Alert{
					Timestamp: time.Now().Format("15:04:05"),
					Source:    ip,
					Message:   fmt.Sprintf("Flooding detected: %d pkts/sec", count),
					Type:      "FLOOD",
				}

				broadcast <- floodAlert

				//add IP to blacklist
				expiration := time.Now().Add(60 * time.Second)
				blacklist.Store(ip, expiration)
			}
			return true
		})

		// Only open the file if we actually have something to report
		if logHighRate != "" || logIP != "" {
			f, err := os.OpenFile(logName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				f.WriteString(logHighRate)
				f.WriteString(logIP)
				f.Close()              // Close immediately so the data is saved
				fmt.Print(logHighRate) // Also print to terminal so you see it live
				fmt.Print(logIP)
			}
		}
	}
}

// 3. The Main Function (The entry point)
func main() {
	fmt.Println("GoGuard IPS: Defender Node is starting...")
	fmt.Println("Interface: enp0s8 (Target)")

	device := "enp0s8" // may need to set dependent on your own machine
	snapshotLen := int32(1024)
	promiscuous := true
	timeout := 100 * time.Millisecond
	dstIP := "192.168.56.102" //Change to your Ubuntu IP

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

	dateTime := time.Now().Format("2006-01-02_15-04-05")
	logName := fmt.Sprintf("logs/log_%s", dateTime)

	f, err := os.OpenFile(logName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	//Dashboard start
	StartDashboard()
	//Flood defense
	go detectFlooding()

	//Loop through packets
	for packet := range packetSource.Packets() {
		//Look for the IP layer in this packet
		ipLayer := packet.Layer(layers.LayerTypeIPv4)

		//Convert generic ipLayer into IPv4 object to read the source, destination and protocol
		if ipLayer != nil {
			atomic.AddUint64(&totalPackets, 1)

			ip, _ := ipLayer.(*layers.IPv4)

			//perIP tracking
			src := ip.SrcIP.String()
			val, _ := perIP.LoadOrStore(src, new(uint64))

			//check blacklist to see if IP is present
			if val, banned := blacklist.Load(src); banned {
				expiration := val.(time.Time)
				if time.Now().Before(expiration) {
					// Still banned
					fmt.Printf("Packet Dropped from %s (Banned until %s)\n", src, expiration.Format("15:04:05"))
					continue
				} else {
					// Ban expired! Lift the restriction
					blacklist.Delete(src)
					fmt.Printf("Timeout Expired for %s. Re-enabling access.\n", src)
				}
			}

			atomic.AddUint64(val.(*uint64), 1)

			//check if packet has app layer and inspect it
			if ip.DstIP.String() == dstIP {
				appLayer := packet.ApplicationLayer()
				if appLayer != nil {
					inspectPayload(src, appLayer.Payload(), f)
				}
			}
			// Get a human-readable timestamp
			timestamp := time.Now().Format("15:04:05.999999")

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

			_, err := f.WriteString(logPacketInfo)
			if err != nil {
				panic(err)
			}

		}

	}

}
