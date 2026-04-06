
# Blue Team Defence Report- Phase2

## 1. Executive Summary
The objective of this engagement was to evaluate and document the defensive mechanisms GoGuard uses to detect and mitigate the two attack scenarios executed by the Red Team in Phase 2.

- **Packet Fragmentation Defence** — TCP flow reassembly + DPI on accumulated payloads
- **IP Spoofing Defence** — MAC/IP binding cross-referenced against the kernel ARP table

Both attacks were successfully detected and mitigated. A critical gap was identified: while the banlist works as expected, the ban duration does not increment if an attacker continues sending packets while already banned. Additionally, active bans are lost on system restart due to the lack of persistent storage.

| Attack Vector | Defence Technique | Outcome | IPS Response |
|---|---|---|---|
| Packet Splitting (frag_attack.py) | TCP flow buffering + reassembled DPI | Malicious payload identified despite fragmentation | Detected + IP blocked |
| IP Spoofing (spoof_frame.py) | MAC/IP binding + ARP table cross-reference | True source identified behind forged IP | Detected + Real IP banned |

---

## 2. Environment Setup

### 2.1 System Requirements
- Host-only network configuration (isolated environment)
- Kali Linux (Red Team VM)
- Ubuntu VM (Blue Team / target)
- Root/sudo privileges
- GoGuard running on `enp0s9` interface

### 2.2 Network Topology

| Role | OS | IP Address | Interface |
|---|---|---|---|
| Red Team (Attacker) | Kali Linux | 192.168.56.4 | eth1 (Host-Only) |
| Blue Team (Defender) | Ubuntu Server | 192.168.56.10 | enp0s9 (Host-Only) |

Both VMs were connected via a VirtualBox Host-Only network (192.168.56.0/24), completely isolated from the university network.

---

## 3. Defence Scenarios

---

## 3.1 Defence 1: TCP Fragmentation Reassembly (DPI)

### Objective
Prevent an attacker from evading Deep Packet Inspection by splitting a malicious payload across multiple TCP fragments so that no single packet contains the full forbidden keyword.

### Rationale
Most signature-based IPS solutions perform DPI on individual packets. By using Scapy to fragment a message like `SELECT * FROM users;` across multiple TCP segments, an attacker can ensure no single packet triggers a keyword match. GoGuard counters this by maintaining per-flow payload buffers — accumulating all fragments from the same TCP connection and running DPI on the combined stream.

### Execution

**Flow Tracking Data Structures**
```go
// FlowKey uniquely identifies a TCP connection by its 4-tuple
type FlowKey struct {
    SrcIP   string
    DstIP   string
    SrcPort uint16
    DstPort uint16
}

// FlowBuffer tracks the accumulated payload for a single TCP flow
type FlowBuffer struct {
    Payload  []byte
    LastSeen time.Time
    State    TCPState
}

var tcpFlows = make(map[FlowKey]*FlowBuffer)
```

**TCP State Machine** — detects data arriving without a prior SYN (stateless injection)
```go
switch {
case tcp.SYN && !tcp.ACK:
    flow.State = TCPStateSYNSeen
case tcp.ACK && flow.State == TCPStateSYNSeen:
    flow.State = TCPStateEstablished
}
```

**Reassembly + DPI Loop** (`main.go:427–447`)
```go
// Append each packet's payload to the flow buffer
flow.Payload = append(flow.Payload, tcp.Payload...)

// Scan the ENTIRE buffer for danger keywords
window := strings.ToUpper(string(flow.Payload))
for _, keyword := range dangerZone {
    if strings.Contains(window, strings.ToUpper(keyword)) {
        executeBan(src, 1, "DPI_THREAT")
    }
}
```

How it works:
- Packet 1: `"SEL"` → buffer = `"SEL"` → no match
- Packet 2: `"ECT * FROM users;"` → buffer = `"SELECT * FROM users;"` → **MATCH → BAN**

### Results
> ✅ **Success:** GoGuard successfully identified the malicious intent even though the payload was split across two packets. The DPI logic reassembled the fragments and correctly banned the source IP.

- The split `SEL` and `ECT` fragments were correlated within the same flow buffer
- A DPI match was triggered on the full `SELECT` keyword
- The attacker's IP was added to the banlist and packets were dropped

**Evidence — Red Team terminal (Kali) running frag_attack.py:**

![Kali attack terminal](RED/images2/kali_attack_terminal.png)

The terminal confirms Fragment 1 (`SEL`) and Fragment 2 (`ECT * FROM users;`) were sent sequentially, with the script instructing to check GoGuard for `DPI_THREAT`.

**Evidence — GoGuard SOC Dashboard:**

![Ubuntu Log](RED/images2/ubuntu_frag_log.png)

![GoGuard dashboard fullscreen](RED/images2/goguard_dashboard_fullscreen.png)

The dashboard confirms the IP was blacklisted and the traffic throughput spike was captured, with the flood dropping to zero after the ban was applied.

### Analysis
The fragmentation defence successfully prevented keyword-splitting evasion. By buffering and reassembling TCP fragments per flow, GoGuard ensures signatures like `SELECT` cannot be hidden by partitioning them across packets.

However, continuing the attack from a banned IP does not extend the ban duration — punishment remains static. Additionally, because the banlist is in-memory, restarting GoGuard immediately clears all active blocks.

---

## 3.2 Defence 2: IP Spoofing Detection

### Objective
Identify packets with forged source IP addresses and ban the real attacker rather than the fake source, preventing IP-rotation techniques from rendering the per-IP banlist useless.

### Rationale
GoGuard bans by source IP. By rotating spoofed IPs on every packet, an attacker can stay under the radar indefinitely. Since a MAC address operates at Layer 2 and cannot be forged within the same LAN segment, GoGuard cross-references each packet's MAC address against both its learned MAC-to-IP bindings and the kernel's ARP table. A mismatch reveals the real attacker behind the forged IP.

### Execution

**MAC/IP Binding Maps** (`main.go:77–82`)
```go
// IP → MAC (learned from observed traffic)
var macIPBinding sync.Map

// MAC → IP (reverse lookup)
var macToIP sync.Map
```

**ARP Table Lookup — Authoritative Source** (`main.go:214–229`)
```go
func arpLookupByMAC(mac string) string {
    // Read the kernel's ARP table from /proc/net/arp
    data, err := os.ReadFile("/proc/net/arp")
    // Returns the IP the kernel associates with this MAC
}
```

**Spoof Detection Logic** (`main.go:240–330`)
```go
func checkMACIPBinding(packet gopacket.Packet, srcIP string, logFile *os.File) bool {
    ethLayer := packet.Layer(layers.LayerTypeEthernet)
    srcMAC := eth.SrcMAC.String()

    // Check ARP table — kernel says which IP this MAC really belongs to
    arpIP := arpLookupByMAC(srcMAC)
    if arpIP != "" && arpIP != srcIP {
        // Mismatch — srcIP is forged, real attacker = arpIP
        spoofDetected = true
        realAttackerIP = arpIP
    }

    // Also check our learned maps
    if existingMAC, known := macIPBinding.Load(srcIP); known &&
        existingMAC.(string) != srcMAC {
        spoofDetected = true
    }

    // Ban the REAL attacker, not the forged IP
    executeBan(realAttackerIP, 1, "IP_SPOOF")
}
```

How it works:
- Real attacker `192.168.56.4` sends packet with forged `srcIP = 192.168.56.200`, real `srcMAC = 08:00:27:de:91:19`
- GoGuard checks `/proc/net/arp` → kernel says that MAC = `192.168.56.4`
- Packet claims `srcIP = 192.168.56.200` → **MISMATCH → BAN `192.168.56.4`**

### Results
> ✅ **Success:** High rate spoofed activity detected across all packets. GoGuard correctly identified the true sender and banned the real attacker IP, not the forged addresses.

**Evidence — Ubuntu kernel log:**

![Ubuntu spoof kernel log](RED/images2/ubuntu_spoof_kernel_log.png)

The log shows repeated `!!! SPOOF DETECTED: forged src IP=192.168.56.200 (victim), real sender MAC=08:00:27:de:91:19 → IP=192.168.56.4` alerts, with each spoofed packet dropped because the real sender was already banned.

**Evidence — GoGuard SOC Dashboard (Live Threat Feed):**



The Live Threat Feed shows repeated `IP spoofing: forged src=192.168.56.200 (victim). Real sender banned.` alerts with millisecond-level timestamps, confirming real-time detection. The traffic throughput graph shows the sharp spike from the attack burst followed by an immediate drop to zero after the ban was applied.

**Evidence — Active Bans confirmed in dashboard:**



The Active Bans panel confirms `192.168.56.4` (the real attacker) was banned — not the forged `192.168.56.200`.

### Analysis
The IP spoofing defence worked effectively. GoGuard correctly traced the attack back to the true physical sender using the kernel ARP table as an authoritative source, rendering IP rotation useless on this LAN segment.

However, this simulation used a calm sequential packet send. A high-volume DDoS-style attack with many packets from each spoofed source simultaneously may stress the ARP lookup mechanism. Additionally, this defence only applies within the same Layer 2 segment — it would not identify spoofed sources routed across subnets.

---

## 4. Key Findings

### 4.1 Strengths of GoGuard

- **Stateful TCP Reassembly** — payloads are buffered per flow and DPI runs on the full reassembled stream, defeating keyword-splitting evasion
- **MAC/ARP Spoof Detection** — correctly identifies the true attacker behind forged IPs using kernel ARP data as ground truth
- **Automated iptables Mitigation** — bans are enforced at the kernel level with no manual intervention
- **Efficient Design** — BPF filters and concurrent goroutines allow low-latency packet inspection with minimal system overhead
- **Rate-Based Detection** — SYN flood and high-volume traffic triggers a ban within ~1 second of onset

### 4.2 Identified Gaps

| Gap | Description |
|---|---|
| **Non-Incrementing Bans** | Banned IPs can continue attacking without any extension of their ban duration. Punishment is static regardless of continued malicious activity. |
| **Volatile Banlist** | The blacklist is stored in memory — all active bans are lost if GoGuard restarts. |
| **No Session Termination** | Existing connections (e.g. an open SSH session) are not closed even if the source IP is later banned. |

---

## 5. Recommendations

1. **Ban Time Escalation** — Increase the ban duration on each subsequent violation from an already-banned IP (e.g. double the time: 1 min → 2 min → 4 min).
2. **Persistent Ban Storage** — Save the banlist to a file or SQLite database so protections survive service restarts and reboots.
3. **Active Session Termination** — Use `conntrack` to immediately kill established TCP sessions when a source IP is added to the blacklist.

---

## 6. Conclusion

Phase 2 testing demonstrated that GoGuard can stop advanced evasion techniques including TCP payload fragmentation and IP spoofing. The reassembly engine correctly correlated split payloads and triggered DPI alerts on the full reconstructed stream. The MAC/IP binding system reliably traced spoofed packets back to the true sender, ensuring bans were applied to the real attacker rather than forged addresses.

The remaining weaknesses centre on the **persistence** and **severity** of applied mitigations. With persistent ban storage and ban time escalation, GoGuard will move from a reactive detection tool to a more robust prevention system.

---