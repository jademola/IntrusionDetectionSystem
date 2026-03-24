# Red Team Attack Report – Phase 1

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

> 📸 **Screenshot:** (ip a of ubuntu and kali)

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
(images)

### Analysis
The attack exposed a timing gap in GoGuard's enforcement. The IPS operates on a 1-second ticker for flood detection, meaning up to 1 second of traffic can pass before a ban is applied. Hydra's `-t 4` thread count generates enough connection volume to trigger detection, but the correct password was found and authenticated within that detection window.

Furthermore, GoGuard's in-memory blacklist blocks future packets from a banned IP but does not terminate an already-established TCP session. Once the SSH handshake completes, the session exists at the kernel level and GoGuard cannot retroactively close it. This is a fundamental limitation of application-layer IPS without kernel-level session management.


---

## 3.2 Attack 2: SYN Flood (Availability Exhaustion)

### Objective
Simulate a Denial-of-Service (DoS) attack using SYN flooding.

### Rationale
SYN floods exploit TCP handshakes to exhaust server resources, preventing legitimate access. This evaluates:
- Rate-based detection  
- System resilience  
- Mitigation effectiveness  

### Execution
```bash
sudo hping3 -S -p 22 --flood <Target-IP>
```

- Randomizes source IP  
- Simulates distributed attacks  
- Tests IP-blocking limitations  

### IPS Detection Focus
- Spike in SYN packets  
- Incomplete TCP handshakes  
- Traffic anomalies  

### Expected Defense
- Rate-based detection  
- IP blocking (limited with random sources)  
- Logging and alerting  

---

## 4. Execution Procedure

1. Start GoGuard IPS on the Ubuntu machine  
2. Ensure correct network interface is monitored (e.g., `enp0s8`)  
3. Verify SSH service is running  

4. Launch attacks from Kali:
   - Run Hydra for brute force testing  
   - Run hping3 for SYN flood testing  

5. Monitor:
   - Detection logs  
   - Response time  
   - iptables rules  
