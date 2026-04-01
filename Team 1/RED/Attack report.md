# Phase 1

# Red Team Attack Report

## 1. Executive Summary
The objective of this engagement was to evaluate the effectiveness of the GoGuard Intrusion Prevention System (IPS) in detecting and mitigating high-severity network attacks in real time. Two attacks scenarios were executed from an isolated Red Team virtual machine targeting the Blue Team's Ubuntu Server running goguard. 

- **Credential Access Attack** (SSH Brute Force using Hydra)
- **Availability Attack** (SYN Flood / Denial of Service using hping3)

These attacks simulate realistic adversarial behavior targeting both **authentication mechanisms** and **system availability**. The evaluation focused on:
- Detection accuracy  
- Response time  
- Effectiveness of automated mitigation (iptables enforcement)

The evaluation focused on detection accuracy response time, and the effectiveness of automated mitigation via iptables enforcement. Both attacks were successfully executed and partially detected. A critical gap was identified: while the SYN flood was detected and the attacker IP banned, the SSH brute force resulted in a successful authenticated login despite detection being active, demonstrating that **detection alone does not constitute prevention**

| Attack Vector | Tool | Outcome | IPS Response |
|---|---|---|---|
| SSH Brute Force | Hydra | Valid password found; login succeeded | Detected — login not blocked |
| SYN Flood (DoS) | hping3 | 500+ pkt/s flood triggered alert | Detected + IP banned |

---

## 2. Environment Setup

### 2.1 System Requirements
- Host-only network configuration (isolated environment)
- Kali Linux (Red Team VM)
- Ubuntu VM (Blue Team / target)
- Root/sudo privileges
- Tools:
  - Hydra
  - hping3
  - modified rockyou.txt wordlist
- Reachable target IP
- Open port (e.g., SSH on port 22)
- Password wordlist (e.g., `rockyou.txt`)

### 2.2 Network Topology

| Role | OS | IP Address | Interface |
|---|---|---|---|
| Red Team (Attacker) | Kali Linux | 192.168.56.4 | eth1 (Host-Only) |
| Blue Team (Defender) | Ubuntu Server | 192.168.56.10 | enp0s9 (Host-Only) |

Both VMs were connected via a VirtualBox Host-Only network (192.168.56.0/24), completely isolated from the university network. GoGuard was configured to monitor the `enp0s9` interface specifically.

**Ubuntu Server (Blue Team) — `ip a`:**

![ip a ubuntu](images/ip%20a%20ubuntu.png)

**Kali Linux (Red Team) — `ip a`:**

![ip a kali](images/ip%20a%20kali.png)

---

## 3. Attack Scenarios

---

## 3.1 Attack 1: SSH Brute Force (Credential Access)

### Objective
Simulate unauthorized access attempts by systematically guessing SSH passwords using a known wordlist. The goal was to determine whether GoGuard could detect abnormal authentication patterns and block the attacker before a valid credential was found.

### Rationale
SSH Brute Force is one of the most prevalent real-world attack vectors against internet-facing Linux servers. Automated tools like Hydra can attempt hundreds of passwords per minute against the SSH daemon on port 22. A capable IPS should detect the high frequency of failed authentication attempts — characterized by repeated TCP SYN/ACK sequences on port 22 that do not result in sustained data transfer — and automatically ban the source IP before a successful login occurs.

This attack specifically tests GoGuard's per-IP packet rate tracking and its ability to correlate repeated connection failures into a coherent threat signal.

### Execution

**Wordlist preparation**
A custom wordlist was created by taking the first 100 entries from rockyou.txt and appending the correct target password at the end, ensuring Hydra would make enough failed attempts to trigger detection before finding the valid credential:

```bash
head -100 /usr/share/wordlists/rockyou.txt > ~/wordlist.txt
echo 'TARGET_PASSWORD' >> ~/wordlist.txt
```

**Attack Command**
```bash
hydra -l johanes -P ~/wordlist.txt ssh://192.168.56.10 -t 4 -vV
```

### Parameters
| Flag | Description |
|---|---|
| `-l johanes` | Target username — the known account on the Ubuntu machine |
| `-P ~/wordlist.txt` | Custom wordlist with correct password at position 101 |
| `ssh://192.168.56.10` | Target SSH service on Blue Team VM |
| `-t 4` | 4 parallel threads — generates enough noise to trigger rate-based detection |
| `-vV` | Verbose mode showing each attempt and result in real time |

### IPS Detection Focus
- High frequency SSH attempts  
- Repeated failed logins  
- Incomplete session establishment  

### Expected Defense
- Detect abnormal login behavior  
- Trigger alerts  
- Block attacker IP via iptables  

### Results
> ⚠️ **Critical Finding:** GoGuard detected the brute force activity but did NOT prevent the successful SSH login. The session was established despite active detection.

- Hydra successfully iterated through 100+ incorrect passwords
- GoGuard logged repeated connection attempts from 192.168.56.4
- The correct password was found and Hydra reported a successful login
- SSH auth.log confirmed the session was opened and closed (Hydra verified the credential and disconnected)

**Evidence**:
![ssh brute force 1](images/ssh%20bruteforce%201.jpeg)

![ssh brute force 2](images/ssh%20bruteforce%202.jpeg)

those two images shows that even though it is detected (image 1), it will still allow login (image 2)

Accepted password for johanes from 192.168.56.4 port 46902 ssh2
pam_unix(sshd:session): session opened for user johanes(uid=1000)
pam_unix(sshd:session): session closed for user johanes

![ssh brute force 3](images/ssh%20bruteforce%203.png)

![ssh brute force 4](images/ssh%20bruteforce%204.png)

It detects well, but still allows ssh login, after multiple attempt.

### Analysis
The attack exposed a timing gap in GoGuard's enforcement. The IPS operates on a 1-second ticker for flood detection, meaning up to 1 second of traffic can pass before a ban is applied. Hydra's `-t 4` thread count generates enough connection volume to trigger detection, but the correct password was found and authenticated within that detection window.

Furthermore, GoGuard's in-memory blacklist blocks future packets from a banned IP but does not terminate an already-established TCP session. Once the SSH handshake completes, the session exists at the kernel level and GoGuard cannot retroactively close it. This is a fundamental limitation of application-layer IPS without kernel-level session management.


---

## 3.2 Attack 2: SYN Flood (Availability Exhaustion)

### Objective
Simulate a Denial-of-Service (DoS) attack by flooding the target with SYN packets, exhausting its TCP connection table and making it unable to respond to legitimate traffic.

### Rationale
SYN floods exploit TCP handshakes to exhaust server resources, preventing legitimate access. This evaluates:
- Rate-based detection  
- System resilience  
- Mitigation effectiveness  

### Execution
```bash
sudo hping3 -S --flood -V -p 22 192.168.56.10
```
- Randomizes source IP  
- Simulates distributed attacks  
- Tests IP-blocking limitations

### Parameters Explained
| Flag | Description |
|---|---|
| `-S` | Sets only the SYN flag — simulates TCP handshake without completing it |
| `--flood` | Sends packets as fast as possible with no delay |
| `-V` | Verbose mode showing packet count and transmission statistics |
| `-p 22` | Targets SSH port specifically |

### IPS Detection Focus
- Spike in SYN packets  
- Incomplete TCP handshakes  
- Traffic anomalies  

### Expected Defense
- Rate-based detection  
- IP blocking (limited with random sources)  
- Logging and alerting  

### Results
- hping3 generated well over 500 SYN packets per second
- GoGuard's `detectFlooding()` goroutine triggered the high-rate alert within 1 second
- Attacker IP (192.168.56.4) was added to GoGuard's in-memory blacklist
- GoGuard began dropping all subsequent packets from the attacker IP

**Evidence**:
![syn flood detected 1](images/syn%20flood%20detected.jpeg)

![syn flood detected 2](images/syn%20flood%20detected2.png)

High rate activity successfully detected (image 1) and packets dropped since ip from kali is banned

### Analysis:
The SYN flood detection worked effectively. The 1-second ticker in `detectFlooding()` provided near-real-time response. The ban duration of 60 seconds was sufficient to interrupt the attack window.

However, a key limitation was identified: the `--rand-source` flag was not used in this test. If randomized source IPs had been used, the per-IP ban would be completely ineffective since each packet would appear to originate from a different address — a realistic scenario in distributed denial-of-service (DDoS) attacks.

---

## 4. Key Findings

### 4.1 Strengths of GoGuard

- SYN flood detected within 1 second of attack onset via rate-based goroutine
- Per-IP packet rate tracking correctly identified and banned 192.168.56.4
- In-memory blacklist with 60-second expiry provided effective temporary blocking
- Modular architecture (BPF filters, goroutines) allows targeted interface monitoring
- Promiscuous mode packet capture ensures no traffic is missed on the monitored interface

### 4.2 Identified Gaps

| Gap | Description |
|---|---|
| BPF filter excluded port 22 | SSH attacks were completely invisible to GoGuard until the filter was manually corrected |
| Detection ≠ Prevention | SSH brute force was detected but the successful login was not blocked |
| Response time gap | The 1-second detection window allows credential validation to succeed before the ban is applied |
| In-memory blacklist | Bans reset when GoGuard restarts — not persistent across sessions |
| rand-source vulnerability | SYN floods with randomized source IPs bypass per-IP banning entirely |
| Hardcoded dstIP | Destination IP for DPI was hardcoded to 192.168.56.102, requiring manual correction |

---

## 5. Recommendations for Blue Team

1. **Implement SSH session termination** — use iptables connection tracking (`conntrack`) to kill established sessions from banned IPs, not just block new packets
2. **Enable SYN cookies** at the kernel level as a complement to application-layer detection: `sysctl -w net.ipv4.tcp_syncookies=1`
3. **Persist iptables rules** using `iptables-save` so bans survive a GoGuard restart
4. **Interface-level rate limiting** for rand-source flood mitigation, rather than per-IP banning
5. **Remove port 22 from BPF exclusion** or add a dedicated SSH authentication failure rate monitor
6. **Make dstIP dynamic** — detect it automatically from the interface rather than hardcoding

---

## 6. Conclusion

Both attacks were successfully executed within the isolated lab environment. GoGuard demonstrated effective flood detection and automated IP banning for the SYN flood attack. However, the SSH brute force test revealed a critical gap — detection without prevention. The system identified the attack but could not stop the authenticated session from being established.

This exercise provided practical insight into the real challenges of host-based intrusion prevention: blocking attacks at the correct stage in the connection lifecycle, the limitations of rate-based detection against evasion techniques like source IP randomization, and the operational importance of monitoring the correct network interface. These findings directly inform the improvements needed in Phase 2 of the GoGuard development roadmap.

---


# Blue Team Defense Report

## 1. Executive Summary
The objective of this engagement was to evaluate the effectiveness of the GoGuard Intrusion Prevention System (IPS) in detecting and mitigating high-severity network attacks in real time. Two attacks scenarios were executed from an isolated Red Team virtual machine targeting the Blue Team's Ubuntu Server running goguard. 

- **Credential Access Attack** (SSH Brute Force using Hydra)
- **Availability Attack** (SYN Flood / Denial of Service using hping3)

These attacks simulate realistic adversarial behavior targeting both **authentication mechanisms** and **system availability**. The evaluation focused on:
- Detection accuracy  
- Response time  
- Effectiveness of automated mitigation (iptables enforcement)

The evaluation focused on detection accuracy response time, and the effectiveness of automated mitigation via iptables enforcement. Both attacks were successfully executed and partially detected. While the Red Team points out the failed protection provided by the system in the case of a SSH Brute Force attack, it brings into question the goal of the system. Do we want to build an Intrusion Detection or Intrusion Prevention System. The key difference being that an IPS will make decisions while an IDS simply makes alerts.

| Defensive Method | Tool | Outcome |
|---|---|---|
| SSH Detection | Port & Payload Detection | Detected attempts at SSH brute force |
| SYN Flood (DoS) | detectFlooding() packet counter | 500+ pkt/s flood triggered alert | 

---

## 2. Environment Setup

### 2.1 System Requirements
- Host-only network / adapter configuration (isolated environment)
- Kali Linux (Red Team VM)
- Ubuntu VM (Blue Team / target)
- Root/sudo privileges
- Scripts:
  - main.go
### 2.2 Network Topology

| Role | OS | IP Address | Interface |
|---|---|---|---|
| Red Team (Attacker) | Kali Linux | 192.168.56.x | eth1 (Host-Only) |
| Blue Team (Defender) | Ubuntu Server | 192.168.56.x | enp0s9 (Host-Only) |

Both VMs were connected via a VirtualBox Host-Only network (192.168.56.0/24), completely isolated from the university network. GoGuard was configured to monitor the `enp0s9` interface specifically.

**Ubuntu Server (Blue Team) — `ip a`:**

![ip a ubuntu](images/ip%20a%20ubuntu.png)

**Kali Linux (Red Team) — `ip a`:**

![ip a kali](images/ip%20a%20kali.png)

---

## 3. Attack Scenarios (Defensive Perspective)

---

## 3.1 Attack 1: SSH Brute Force (Credential Access)

### Objective
Simulate unauthorized access attempts by systematically guessing SSH passwords using a known wordlist. The goal was to determine whether GoGuard could detect abnormal authentication (TCP) patterns.

### Rationale
SSH Brute Force is one of the most prevalent real-world attack vectors against internet-facing Linux servers. Automated tools like Hydra can attempt hundreds of passwords per minute against the SSH daemon on port 22. A capable IPS should detect the high frequency of failed authentication attempts — characterized by repeated TCP SYN/ACK sequences on port 22 that do not result in sustained data transfer.


### Execution

**Packet Inspection**
By inspecting the packet payload we can identify whether the TCP packet is indeed a SSH login attempt. This is identified by `SSH-` being included in the payload prefix. We can also check to see if the port being sent packets is port 22 (default for SSH requests)

**Check**
```golang
tcp := tcpLayer.(*layers.TCP)
	isSSH := tcp.DstPort == 22 || (len(tcp.Payload) > 0 && strings.HasPrefix(string(tcp.Payload), "SSH-"))
```

**Banning & Brute Force Attribution**
```golang
if isSSH && tcp.SYN && !tcp.ACK {
		val, _ := sshPerIP.LoadOrStore(src, new(uint64))
		count := atomic.AddUint64(val.(*uint64), 1)
		if count >= 3 {
			executeBan(src, count, "SSH_BRUTE")
			return true
		}
	}
```

### IPS Detection Focus
- High frequency SSH attempts  
- Repeated failed logins  
- Incomplete session establishment  

### Expected Defense
- Detect abnormal login behavior  
- Trigger alerts  
- Block attacker IP via iptables  

### Results
> ⚠️ **Critical Finding:** GoGuard detected the brute force activity but did NOT prevent the successful SSH login. The session was established despite active detection.

- Hydra successfully iterated through 100+ incorrect passwords
- GoGuard logged repeated connection attempts from 192.168.56.4
- The correct password was found and Hydra reported a successful login
- SSH auth.log confirmed the session was opened and closed (Hydra verified the credential and disconnected)

**Evidence**:
![ssh brute force 1](images/ssh%20bruteforce%201.jpeg)

![ssh brute force 2](images/ssh%20bruteforce%202.jpeg)

those two images shows that even though it is detected (image 1), it will still allow login (image 2)

Accepted password for johanes from 192.168.56.4 port 46902 ssh2
pam_unix(sshd:session): session opened for user johanes(uid=1000)
pam_unix(sshd:session): session closed for user johanes

![ssh brute force 3](images/ssh%20bruteforce%203.png)

![ssh brute force 4](images/ssh%20bruteforce%204.png)

It detects well, but still allows ssh login, after multiple attempt.

### Analysis
The attack exposed a timing gap in GoGuard's enforcement. The IPS operates on a 1-second ticker for flood detection, meaning up to 1 second of traffic can pass before a ban is applied. Hydra's `-t 4` thread count generates enough connection volume to trigger detection, but the correct password was found and authenticated within that detection window.

Furthermore, GoGuard's in-memory blacklist blocks future packets from a banned IP but does not terminate an already-established TCP session. With this in mind, we have to reconsider if the system is built to both detect and prevent. If following known patterns such as brute forcing, the system should not allow these attempts through. Any unknown alerts should have different, more alert-based behavior.


---

## 3.2 Attack 2: SYN Flood (Availability Exhaustion)

### Objective
Simulate a Denial-of-Service (DoS) attack by flooding the target with SYN packets, exhausting its TCP connection table and making it unable to respond to legitimate traffic.

### Rationale
SYN floods exploit TCP handshakes to exhaust server resources, preventing legitimate access. This evaluates:
- Rate-based detection  
- System resilience  
- Mitigation effectiveness  

### Execution

**Flooding Detection & Ban**
```golang
func detectFlood(src string) bool {
	val, _ := perIP.LoadOrStore(src, new(uint64))
	count := atomic.AddUint64(val.(*uint64), 1)
	if count > 500 {
		executeBan(src, count, "FLOOD")
		return true
	}
	return false
}
```


### IPS Detection Focus
- Spike in SYN packets  
- Incomplete TCP handshakes  
- Traffic anomalies  

### Expected Defense
- Rate-based detection  
- IP blocking (limited with random sources)  
- Logging and alerting  

### Results
- hping3 generated well over 500 SYN packets per second
- GoGuard's `detectFlooding()` goroutine triggered the high-rate alert within 1 second
- Attacker IP (192.168.56.x) was added to GoGuard's in-memory blacklist
- GoGuard began dropping all subsequent packets from the attacker IP

**Evidence**:
![syn flood detected 1](images/syn%20flood%20detected.jpeg)

![syn flood detected 2](images/syn%20flood%20detected2.png)

High rate activity successfully detected (image 1) and packets dropped since ip from kali is banned

### Analysis:
> The SYN flood detection worked effectively. The 1-second ticker in `detectFlooding()` provided near-real-time response. The ban duration of 60 seconds was sufficient to interrupt the attack window.

> However, a key limitation was identified: the `--rand-source` flag was not used in this test. If randomized source IPs had been used, the per-IP ban would be completely ineffective since each packet would appear to originate from a different address — a realistic scenario in distributed denial-of-service (DDoS) attacks.

In order to combat this, we would have to either change the IP address of the server to another within our network. Most DDos attacks target specific services and this could be mitigated by creating a honeypot, and adding any source IPs to a blocklist.

---

## 4. Key Findings

### 4.1 Strengths of GoGuard

- SYN flood detected within 1 second of attack onset via rate-based goroutine
- Per-IP packet rate tracking correctly identified and banned 192.168.56.4
- In-memory blacklist with 60-second expiry provided effective temporary blocking
- Modular architecture (BPF filters, goroutines) allows targeted interface monitoring
- Promiscuous mode packet capture ensures no traffic is missed on the monitored interface

### 4.2 Identified Gaps

| Gap | Description |
|---|---|
| BPF filter excluded port 22 | SSH attacks were completely invisible to GoGuard until the filter was manually corrected |
| Detection ≠ Prevention | SSH brute force was detected but the successful login was not blocked |
| Response time gap | The 1-second detection window allows credential validation to succeed before the ban is applied |
| In-memory blacklist | Bans reset when GoGuard restarts — not persistent across sessions |
| rand-source vulnerability | SYN floods with randomized source IPs bypass per-IP banning entirely |
| Hardcoded dstIP | Destination IP for DPI was hardcoded to 192.168.56.102, requiring manual correction |

---

## 6. Conclusion

From the Blue Team perspective, the exercise confirmed that GoGuard can detect and disrupt high-volume availability attacks in real time, as shown by successful SYN flood detection and automated source blocking. At the same time, our defensive review identified a critical weakness in SSH protection: brute-force behavior was detected, but the control path did not prevent a valid authenticated session from being established.

These results clarify our Phase 2 priorities as defenders: enforce mitigation earlier in the connection lifecycle, strengthen protections against source-randomized floods, and harden operational reliability through correct interface visibility and persistent controls. In short, our detection capabilities are promising, but prevention depth must be improved before GoGuard can be considered a mature system.

---

