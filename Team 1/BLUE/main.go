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

// Longest keyword length, used for sliding window in flow reassembly
var maxKeywordLen int

func init() {
	for _, kw := range dangerZone {
		if len(kw) > maxKeywordLen {
			maxKeywordLen = len(kw)
		}
	}
}

// FlowKey uniquely identifies a TCP connection by its 4-tuple
type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

// TCPState tracks the handshake progress of a TCP flow
type TCPState uint8

const (
	TCPStateNone        TCPState = 0 // No packets seen yet
	TCPStateSYNSeen     TCPState = 1 // SYN received, waiting for ACK
	TCPStateEstablished TCPState = 2 // Handshake complete
)

// FlowBuffer tracks the accumulated payload for a single TCP flow
type FlowBuffer struct {
	Payload  []byte
	LastSeen time.Time
	State    TCPState // handshake state for spoof detection
}

var tcpFlows = make(map[FlowKey]*FlowBuffer)
var flowsMu sync.Mutex

// macIPBinding stores the first-seen MAC address for each source IP.
var macIPBinding sync.Map // map[string]string  (IP → MAC)

// macToIP is the reverse: first-seen IP for each MAC address.
// This lets us identify the real sender when they forge a different source IP.
var macToIP sync.Map // map[string]string  (MAC → IP)

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

	// If it is in the map, it is banned.
	expiration := val.(time.Time)
	fmt.Printf("Packet Dropped from %s (Banned until %s)\n", src, expiration.Format("15:04:05"))
	return true
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

	// --- NEW: THE BACKGROUND TIMER ---
	go func(targetIP string) {
		// Wait exactly 60 seconds in the background
		time.Sleep(60 * time.Second)

		// 1. Remove Kernel Block
		cmd := exec.Command("sudo", "iptables", "-D", "INPUT", "-s", targetIP, "-j", "DROP")
		cmd.Run()

		// 2. Clean up Go memory
		blacklist.Delete(targetIP)

		// 3. Notify Dashboard and Console
		fmt.Printf("Timeout Expired for %s. Re-enabling access.\n", targetIP)
		broadcast <- Alert{
			Timestamp: time.Now().Format("15:04:05"),
			Source:    targetIP,
			Type:      "UNBAN",
			Message:   "Ban Expired",
		}
	}(ip)
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

// arpLookupByMAC scans /proc/net/arp for the IP the kernel associates with
// the given MAC. The kernel populates this from real ARP traffic, so it
// cannot be poisoned by our application state.
func arpLookupByMAC(mac string) string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n")[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) >= 4 && strings.EqualFold(fields[3], mac) {
			return fields[0]
		}
	}
	return ""
}

// checkMACIPBinding detects IP spoofing using two cross-referenced maps:
//  1. macIPBinding (IP → MAC): if an IP arrives with a different MAC than
//     previously learned, the IP is forged.
//  2. macToIP (MAC → IP): if a MAC arrives claiming a different IP than
//     previously learned, the source IP is forged and the real attacker is
//     the IP that was originally associated with that MAC.
//
// When a spoof is confirmed the real attacker's IP is banned.
// Returns true if spoofing was detected (caller should drop the packet).
func checkMACIPBinding(packet gopacket.Packet, srcIP string, logFile *os.File) bool {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return false
	}
	eth := ethLayer.(*layers.Ethernet)
	srcMAC := eth.SrcMAC.String()

	// Ignore broadcast / unset MACs
	if srcMAC == "ff:ff:ff:ff:ff:ff" || srcMAC == "00:00:00:00:00:00" {
		return false
	}

	spoofDetected := false
	realAttackerIP := ""

	// ARP check — most authoritative, runs first.
	// The kernel populates /proc/net/arp from real ARP traffic; it cannot be
	// poisoned by our application state.
	//
	// Two outcomes:
	//   arpIP != srcIP  → ARP confirms this MAC belongs to a different host →
	//                     srcIP is forged; real attacker = arpIP.
	//   arpIP == srcIP  → ARP confirms this MAC legitimately belongs to srcIP →
	//                     packet is clean even if our learned maps say otherwise
	//                     (maps may be poisoned by a prior spoofed packet).
	arpIP := arpLookupByMAC(srcMAC)
	if arpIP != "" {
		if arpIP != srcIP {
			spoofDetected = true
			realAttackerIP = arpIP
		} else {
			// ARP confirms legitimacy — trust it over the learned maps,
			// correct any poisoned entries, and return clean.
			macToIP.Store(srcMAC, srcIP)
			macIPBinding.Store(srcIP, srcMAC)
			return false
		}
	}

	// Learned map checks — fallback when ARP has no entry for this MAC yet.
	// Use Load (not LoadOrStore) so spoofed packets never pollute the maps.
	if !spoofDetected {
		if existingIP, ipKnown := macToIP.Load(srcMAC); ipKnown && existingIP.(string) != srcIP {
			spoofDetected = true
			realAttackerIP = existingIP.(string)
		}
		if existingMAC, macKnown := macIPBinding.Load(srcIP); macKnown && existingMAC.(string) != srcMAC {
			spoofDetected = true
		}
	}

	if !spoofDetected {
		// Packet is clean — record the MAC/IP association for future checks.
		macToIP.Store(srcMAC, srcIP)
		macIPBinding.Store(srcIP, srcMAC)
		return false
	}

	timestamp := time.Now().Format("15:04:05.999999")
	alertMsg := fmt.Sprintf(
		"[%s] !!! SPOOF DETECTED: forged src IP=%s (victim), real sender MAC=%s → IP=%s\n",
		timestamp, srcIP, srcMAC, realAttackerIP,
	)

	fmt.Print(alertMsg)
	if logFile != nil {
		logFile.WriteString(alertMsg)
	}

	broadcast <- Alert{
		Timestamp: timestamp,
		Source:    realAttackerIP,
		Message:   fmt.Sprintf("IP spoofing: forged src=%s (victim). Real sender banned.", srcIP),
		Type:      "SPOOF_DETECTED",
	}

	// Ban the real attacker, not the victim whose IP was forged.
	// Guard against re-banning: the spoofed srcIP bypasses the blacklist check
	// in the main loop, so we must check here whether the real attacker is
	// already banned before calling executeBan again.
	if realAttackerIP != "" {
		if _, alreadyBanned := blacklist.Load(realAttackerIP); !alreadyBanned {
			executeBan(realAttackerIP, 1, "IP_SPOOF")
		} else {
			fmt.Printf("Spoofed packet dropped (real sender %s already banned)\n", realAttackerIP)
		}
	}

	return true
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

// reassembleAndInspectTCP accumulates TCP payloads per flow and runs DPI
// against a sliding window of the concatenated buffer. This catches attacks
// that split malicious keywords across multiple packets (fragmentation evasion).
func reassembleAndInspectTCP(packet gopacket.Packet, src string, dstIP string, logFile *os.File) bool {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}
	tcp := tcpLayer.(*layers.TCP)
	fmt.Printf("DEBUG TCP: src=%s payload_len=%d payload=%q\n", src, len(tcp.Payload), string(tcp.Payload))

	key := FlowKey{
		SrcIP:   src,
		DstIP:   dstIP,
		SrcPort: uint16(tcp.SrcPort),
		DstPort: uint16(tcp.DstPort),
	}

	flowsMu.Lock()
	defer flowsMu.Unlock()

	flow, exists := tcpFlows[key]
	if !exists {
		flow = &FlowBuffer{State: TCPStateNone}
		tcpFlows[key] = flow
	}
	flow.LastSeen = time.Now()

	// --- TCP State Machine ---
	// Update handshake state based on flags (must happen before payload check
	// so SYN-only packets, which carry no payload, still advance the state).
	switch {
	case tcp.SYN && !tcp.ACK:
		flow.State = TCPStateSYNSeen
	case tcp.ACK && flow.State == TCPStateSYNSeen:
		flow.State = TCPStateEstablished
	}

	if len(tcp.Payload) == 0 {
		return false
	}

	// --- Stateless Data Detection ---
	// A data-bearing packet with no prior SYN could be a raw injection attack
	// (e.g. frag attack from the real attacker) or IP spoofing. We log it but
	// still continue to DPI so the payload is inspected and the real attacker
	// can be banned. True IP spoofing (MAC mismatch) is caught earlier by
	// checkMACIPBinding before this function is ever reached.
	if flow.State == TCPStateNone {
		timestamp := time.Now().Format("15:04:05.999999")
		alertMsg := fmt.Sprintf(
			"[%s] !!! STATELESS INJECTION: Data from %s (flags SYN=%v ACK=%v PSH=%v) with no prior handshake\n",
			timestamp, src, tcp.SYN, tcp.ACK, tcp.PSH,
		)
		fmt.Print(alertMsg)
		if logFile != nil {
			logFile.WriteString(alertMsg)
		}
		broadcast <- Alert{
			Timestamp: timestamp,
			Source:    src,
			Message:   "Stateless data packet — raw injection detected",
			Type:      "STATELESS_INJECTION",
		}
		// Do NOT return — fall through to DPI so the payload is still inspected
		// and the attacker can be identified and banned.
	}

	flow.Payload = append(flow.Payload, tcp.Payload...)
	flow.LastSeen = time.Now()

	// Scan the trailing window (last maxKeywordLen bytes) for danger keywords.
	// This catches keywords that were split across packet boundaries.
	window := strings.ToUpper(string(flow.Payload))

	for _, keyword := range dangerZone {
		if strings.Contains(window, strings.ToUpper(keyword)) {
			timestamp := time.Now().Format("15:04:05.999999")
			alertMsg := fmt.Sprintf("[%s] !!! DPI ALERT (reassembled): Keyword '%s' detected from %s\n",
				timestamp, keyword, src)
			fmt.Print(alertMsg)
			if logFile != nil {
				logFile.WriteString(alertMsg)
			}
			executeBan(src, 1, "DPI_THREAT")
			delete(tcpFlows, key)
			return true
		}
	}
	return false
}

// cleanupFlows removes flow buffers that have been idle for more than 30 seconds
func cleanupFlows() {
	flowsMu.Lock()
	defer flowsMu.Unlock()
	cutoff := time.Now().Add(-30 * time.Second)
	for key, flow := range tcpFlows {
		if flow.LastSeen.Before(cutoff) {
			delete(tcpFlows, key)
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

		// Clean up stale TCP flow buffers to prevent memory exhaustion
		cleanupFlows()

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
	dstIP := "192.168.56.10" //Change to your Ubuntu IP

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

		// Step 1.5: MAC-IP binding check — drop spoofed packets without
		// banning the claimed source IP (which is the innocent victim).
		if checkMACIPBinding(packet, src, f) {
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

		// Step 5: Deep Packet Inspection with TCP flow reassembly
		// Buffers payloads per flow to detect keywords split across packets
		fmt.Printf("Debug: dst=%s, dstIP=%s, match=%v\n", ip.DstIP.String(), dstIP, ip.DstIP.String() == dstIP)
		if ip.DstIP.String() == dstIP {
			reassembleAndInspectTCP(packet, src, dstIP, f)
		}

		// Step 6: Record the activity
		logPacket(ip, src, f)
	}
}
