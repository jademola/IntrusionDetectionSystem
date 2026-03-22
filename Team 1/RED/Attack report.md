# Red Team Attack Report – Phase 1

## 1. Executive Summary
The objective of this engagement was to evaluate the effectiveness of the GoGuard Intrusion Prevention System (IPS) in detecting and mitigating high-severity network attacks in real time.  

Two attack scenarios were executed from an isolated Red Team virtual machine:
- **Credential Access Attack** (SSH Brute Force)
- **Availability Attack** (SYN Flood / Denial of Service)

These attacks simulate realistic adversarial behavior targeting both **authentication mechanisms** and **system availability**. The evaluation focused on:
- Detection accuracy  
- Response time  
- Effectiveness of automated mitigation (iptables enforcement)

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
- Reachable target IP
- Open port (e.g., SSH on port 22)
- Password wordlist (e.g., `rockyou.txt`)

---

## 3. Attack Scenarios

---

## 3.1 Attack 1: SSH Brute Force (Credential Access)

### Objective
Simulate unauthorized access attempts by systematically guessing passwords.

### Rationale
Brute force attacks are common against exposed SSH services. This test evaluates whether the IPS can:
- Detect abnormal authentication patterns  
- Identify repeated failed logins  
- Block malicious sources before compromise  

### Execution
```bash
hydra -l <username> -P /usr/share/wordlists/rockyou.txt ssh://<Target-IP> -t 4 -vV
```

### Parameters
- `-l <username>`: Target user  
- `-P`: Password list  
- `-t 4`: Parallel threads  
- `-vV`: Verbose mode  

### IPS Detection Focus
- High frequency SSH attempts  
- Repeated failed logins  
- Incomplete session establishment  

### Expected Defense
- Detect abnormal login behavior  
- Trigger alerts  
- Block attacker IP via iptables  

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
