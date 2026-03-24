// 1. Package Declaration
package main

// 2. Imports (The tools we are borrowing)
import (
	"flag" // for command line args
	"fmt"  //printing to console
	"log"
	"strings"
	"time"

	// for logging
	"os"

	//for iptables
	"os/exec"
	// for nmap counts
	"sync"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers" //To read IP layers
	"github.com/google/gopacket/pcap"
)

var totalPackets uint64
var perIP sync.Map    // map[string]*uint64
var sshPerIP sync.Map // map[string]*uint64
var blacklist sync.Map

// Dangerous keywords used in packet inspection
var dangerZone = []string{
	"SELECT", "DROP", "UNION", "INSERT", // SQL Injection
	"<script>", "alert(", // XSS
	"/etc/passwd", "/etc/shadow", //Linux System File Access
	"admin", "password", "login", // Credential Hunting
}

//----- Defense Functions -----

func detectFlood(src string) bool {
	val, _ := perIP.LoadOrStore(src, new(uint64))
	count := atomic.AddUint64(val.(*uint64), 1)
	if count > 500 {
		executeBan(src, count, "FLOOD")
		return true
	}
	return false
}

func logPacket(ip *layers.IPv4, src string, logFile *os.File) {
	timestamp := time.Now().Format("15:04:05.999999")
	detectionLog := fmt.Sprintf("[%s] Detection: %s --> %s | Proto: %s\n",
		timestamp, src, ip.DstIP, ip.Protocol)

	// Print to terminal for live feedback
	fmt.Print(detectionLog)

	// Save to the persistent log file
	if logFile != nil {
		_, _ = logFile.WriteString(detectionLog)
	}
}

func detectSSHBrute(packet gopacket.Packet, src string) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp := tcpLayer.(*layers.TCP)
	isSSH := tcp.DstPort == 22 || (len(tcp.Payload) > 0 && strings.HasPrefix(string(tcp.Payload), "SSH-"))

	if isSSH && tcp.SYN && !tcp.ACK {
		val, _ := sshPerIP.LoadOrStore(src, new(uint64))
		count := atomic.AddUint64(val.(*uint64), 1)
		if count >= 3 {
			executeBan(src, count, "SSH_BRUTE")
			return true
		}
	}
	return false
}

func processDPI(packet gopacket.Packet, src string, logFile *os.File) {
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		// This still calls your existing inspectPayload function
		inspectPayload(src, appLayer.Payload(), logFile)
	}
}

func isBlacklisted(src string) bool {
	val, banned := blacklist.Load(src)
	if !banned {
		return false
	}

	expiration := val.(time.Time)
	if time.Now().Before(expiration) {
		// --- KERNEL ENFORCEMENT CHECK ---
		// At this point, the packet has already been dropped by iptables
		// if executeBan ran correctly. We just log it for the dashboard.
		fmt.Printf("Packet Dropped from %s (Banned until %s)\n", src, expiration.Format("15:04:05"))
		return true
	}

	// --- TIMEOUT EXPIRED: REMOVE KERNEL BLOCK ---
	// This physically deletes the DROP rule from the Linux Kernel
	cmd := exec.Command("sudo", "iptables", "-D", "INPUT", "-s", src, "-j", "DROP")
	err := cmd.Run()
	if err != nil {
		// If the rule was already gone (or never existed), we log it but continue
		fmt.Printf("Note: Could not clear iptables rule for %s: %v\n", src, err)
	} else {
		fmt.Printf("Kernel block lifted for %s.\n", src)
	}

	// Clean up Go memory
	blacklist.Delete(src)

	fmt.Printf("Timeout Expired for %s. Re-enabling access.\n", src)
	broadcast <- Alert{
		Timestamp: time.Now().Format("15:04:05"),
		Source:    src,
		Type:      "UNBAN",
		Message:   "Ban Expired",
	}

	return false
}

// Helper for handling ban and broadcasting
func executeBan(ip string, count uint64, reason string) {
	expiration := time.Now().Add(60 * time.Second)
	blacklist.Store(ip, expiration)

	// This adds a rule to the top of the firewall to DROP all traffic from this IP
	cmd := exec.Command("sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error applying iptables rule: %v\n", err)
	}

	// 3. Existing Alerts
	fmt.Printf("!!! %s detected from %s: %d attempts. KERNEL BLOCK APPLIED.\n", reason, ip, count)

	broadcast <- Alert{
		Timestamp: time.Now().Format("15:04:05"),
		Source:    ip,
		Message:   fmt.Sprintf("%s: %d detected", reason, count),
		Type:      reason, // e.g., "SSH_BRUTE" or "FLOOD"
	}

	broadcast <- Alert{
		Timestamp: expiration.Format("15:04:05"),
		Source:    ip,
		Message:   "IP Blacklisted",
		Type:      "BAN",
	}

}

func applyFilters(handle *pcap.Handle) {
	// 2. "not host 192.168.56.1" -> Ignores all traffic FROM or TO your Windows/Mac host
	// 3. "not net 224.0.0.0/4" -> Ignores ALL Multicast traffic (SSDP, mDNS, etc.)
	filter := "not host 192.168.56.1 and not net 224.0.0.0/4"

	err := handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatalf("Error applying BPF filter: %v", err)
	}
	fmt.Println("Network filters active: Host Noise, and Multicast ignored.")
}

func inspectPayload(src string, data []byte, logFile *os.File) {
	// Convert binary payload to string for searching
	payload := string(data)
	upperPayload := strings.ToUpper(payload)

	for _, keyword := range dangerZone {
		if strings.Contains(upperPayload, strings.ToUpper(keyword)) {
			timestamp := time.Now().Format("15:04:05.999999")

			// 1. Log and Terminal Output
			alertMsg := fmt.Sprintf("[%s] !!! DPI ALERT: Keyword '%s' detected from %s\n", timestamp, keyword, src)
			fmt.Print(alertMsg)

			if logFile != nil {
				logFile.WriteString(alertMsg)
			}

			// 2. TRIGGER THE BAN IMMEDIATELY
			// We use '1' as the count because a single DPI match is a high-severity event
			executeBan(src, 1, "DPI_THREAT")

			// 3. Exit on first detection to avoid redundant bans for the same packet
			break
		}
	}
}

func monitorSystemStats() {
	// 1. Setup Directories
	_ = os.MkdirAll("flags", 0755)
	_ = os.MkdirAll("logs/TCP", 0755)
	_ = os.MkdirAll("logs/ICMP", 0755)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	dateTime := time.Now().Format("2006-01-02_15-04-05")
	logName := fmt.Sprintf("flags/log_%s", dateTime)

	for range ticker.C {
		// 2. Statistics Gathering
		// Swap resets the total global counter to 0 for the next second
		totalRate := atomic.SwapUint64(&totalPackets, 0)
		perIPSnapshot := make(map[string]uint64)
		logHighRate := ""

		if totalRate > 5000 {
			logHighRate = fmt.Sprintf("!!! High Total Rate Detected: %d packets/sec\n", totalRate)
		}

		// 3. Map Cleanup
		// We iterate through maps to grab stats for the dashboard AND reset counters
		perIP.Range(func(key, value any) bool {
			ip := key.(string)
			// Resetting here ensures our 'event' triggers in main are per-second
			count := atomic.SwapUint64(value.(*uint64), 0)
			if count > 0 {
				perIPSnapshot[ip] = count
			}
			return true
		})

		// SAFETY: If the map grows too large (e.g., 50k entries), clear it entirely
		// to prevent memory exhaustion from spoofed IP attacks.
		mapCounter := 0
		perIP.Range(func(_, _ any) bool { mapCounter++; return true })
		if mapCounter > 50000 {
			perIP = sync.Map{}
			sshPerIP = sync.Map{}
			fmt.Println("!!! IPS Protection: High map cardinality detected. Clearing cache.")
		}

		sshPerIP.Range(func(key, value any) bool {
			// Just reset the SSH counters; main handles the actual banning now
			atomic.SwapUint64(value.(*uint64), 0)
			return true
		})

		// 4. Dashboard Reporting
		// Global throughput pulse
		broadcast <- Alert{
			Timestamp: time.Now().Format("15:04:05"),
			Source:    "System",
			Message:   fmt.Sprintf("%d", totalRate),
			Type:      "PULSE",
		}

		// Per-IP data for the high-res chart
		broadcast <- Alert{
			Timestamp: time.Now().Format("15:04:05"),
			Source:    "System",
			Type:      "PULSE_PER_IP",
			Series:    perIPSnapshot,
		}

		// 5. Logging to File
		if logHighRate != "" {
			f, err := os.OpenFile(logName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				f.WriteString(logHighRate)
				f.Close()
				fmt.Print(logHighRate)
			}
		}
	}
}

// 3. The Main Function (The entry point)
func main() {
	fmt.Println("GoGuard IPS: Defender Node is starting...")
	fmt.Println("Interface: enp0s8 (Target)")

	ifacePtr := flag.String("iface", "enp0s8", "The network interface to sniff on")

	flag.Parse()

	device := *ifacePtr // may need to set dependent on your own machine
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
	// Background Ticker: Now strictly for Charting and Counter Resets
	go monitorSystemStats()

	// Loop through packets
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}

		ip, _ := ipLayer.(*layers.IPv4)
		src := ip.SrcIP.String()

		// --- THE SECURITY PIPELINE ---

		// Step 1: Check if already banned
		if isBlacklisted(src) {
			continue
		}

		// Step 2: Update global throughput metrics
		atomic.AddUint64(&totalPackets, 1)

		// Step 3: Catch high-volume floods
		if detectFlood(src) {
			continue
		}

		// Step 4: Catch SSH brute force attempts
		if detectSSHBrute(packet, src) {
			continue
		}

		// Step 5: Deep Packet Inspection for malicious keywords
		if ip.DstIP.String() == dstIP {
			processDPI(packet, src, f)
		}

		// Step 6: Record the activity
		logPacket(ip, src, f)
	}
}
