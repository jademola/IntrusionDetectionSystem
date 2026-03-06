# Intrusion Detection System

**Course:** COSC 490 – Student Directed Seminar  
**Group Members:** Ethan Sturek, Jimi Ademola, Johanes Panjaitan, Vanshika Singla  

---

# 1. Abstract

We propose the development of a custom **Host-Based Intrusion Prevention System (IPS)** built using **Go (Golang)** and **Docker**.  

As modern infrastructure shifts toward **containerized environments**, traditional hardware firewalls are often insufficient for microservices.

This project will simulate a **"Red Team vs. Blue Team"** cyber warfare scenario within a **controlled, isolated virtual environment**.

The system will:

- Inspect **network traffic in real-time**
- Detect malicious patterns such as:
  - **SQL Injection**
  - **Brute Force attacks**
- Automatically execute **kernel-level blocking rules**

The goal is to **neutralize threats without human intervention**.

---

# 2. Motivation & Career Relevance

Cybersecurity is rapidly moving toward **Infrastructure as Code** and **high-performance automated defense systems**.

### Why Go?

Go is widely used in **cloud-native security tools** including:

- Docker
- Kubernetes
- CrowdStrike

Key advantages:

- High performance
- Built-in concurrency
- Efficient systems-level programming

### Why Docker?

Containerization is now a **core skill for DevSecOps roles**. Docker allows reproducible infrastructure and easy deployment of monitoring systems.

### Real-World Application

This project mirrors the architecture of enterprise security tools such as:

- Fail2Ban
- Snort

Students will gain hands-on experience with:

- Network protocol analysis
- Systems programming
- Security automation

---

# 3. System Architecture

The system will run inside a **Virtual Lab** composed of **two isolated machines** connected via a **Host-Only Network**.  

This ensures **complete separation from the university network**.

## Node A: Attacker (Red Team)

**Operating System:** Kali Linux  

**Tools:**

- Nmap — reconnaissance and port scanning
- Hydra — brute force attacks
- Hping3 — flooding / DDoS simulation
- Custom Python scripts — SQL injection payloads

---

## Node B: Defender (Blue Team)

**Operating System:** Ubuntu Server  

**Core Engine:**

- Custom Go application
- Uses **gopacket** (libpcap wrapper) for **Deep Packet Inspection (DPI)**

**Data Pipeline:**

- Docker container running **InfluxDB** (time-series database)
- **Grafana** for real-time visualization

**Enforcement:**

- Integration with **Linux iptables**
- Automatically bans malicious IP addresses

---

# 4. Technical Implementation Plan

The system operates on a **"Listen → Analyze → Act"** loop.

## 1. Ingest

The Go application captures packets from the network interface in **promiscuous mode**.

## 2. Analyze

The engine parses:

- TCP headers
- HTTP headers
- Packet payloads

Packets are evaluated against predefined **attack signatures**, such as:

- `' OR 1=1` in HTTP POST bodies
- Rapid SYN packet bursts

## 3. Act

Two response levels are implemented.

**Low Severity**

- Log event to **InfluxDB**
- Display activity on **Grafana dashboard**

**High Severity**

- Execute system call
- Insert **iptables rule** to drop all future traffic from the attacker IP

---

# 5. Project Timeline (7 Weeks)

## Phase 1: Environment & Infrastructure (Weeks 1–2)

Tasks:

- Setup VirtualBox VMs
- Configure **Host-Only networking**
- Deploy Docker containers for:
  - InfluxDB
  - Grafana

**Milestone**

- Successful ping between VMs
- Basic packet capture printed to terminal

---

## Phase 2: Detection Engine (Weeks 3–4)

Tasks:

- Develop Go logic to detect attack signatures

Attack types targeted:

- Port scanning
- SYN floods
- SSH brute force

**Milestone**

- System logs **"Attack Detected"** when Nmap scans the server

---

## Phase 3: Active Defense & Visualization (Weeks 5–6)

Tasks:

- Implement automatic **IP banning**
- Build **Grafana dashboard**

Dashboard metrics:

- Attacks per second
- Banned IP addresses
- Threat visualization

New attack focus:

- SQL injection
- Web exploitation attempts

---

## Phase 4: Stress Testing & Final Report (Week 7)

**Red Team**

- Launch high-volume attacks

**Blue Team**

- Optimize Go routines
- Prevent crashes under heavy load

**Final Report Focus**

- Detection accuracy
- System performance
- System stability under attack

---

# 6. Expected Learning Outcomes

By completing this project, the team will demonstrate proficiency in:

### Network Proficiency
Understanding of:

- TCP/IP handshakes
- Packet structures
- Network traffic analysis

### Systems Programming
Experience writing **low-level, high-performance code in Go**.

### DevSecOps
Hands-on deployment of monitoring systems using:

- Docker
- Grafana
- InfluxDB

### Security Analysis
Practical understanding of:

- Common cyber attack vectors
- Mathematical detection of malicious patterns

---

# 7. Limitations & Scope

While the system demonstrates real-time intrusion detection and automated prevention, several limitations define the project's scope.

## Encrypted Traffic (HTTPS)

The system analyzes **unencrypted packet data** within a controlled lab environment.

Encrypted HTTPS traffic cannot be deeply inspected without:

- TLS termination
- Proxy-based interception

These approaches are **outside the scope of this project**.

---

## Signature-Based Detection

The system primarily relies on:

- Signature-based detection
- Rate-based anomaly detection

Examples include:

- SYN flood thresholds
- Known SQL injection patterns

As a result:

- **Zero-day exploits**
- **Highly obfuscated payloads**

may not be detected.

---

## Controlled Lab Environment

All testing occurs within an **isolated Host-Only virtual network** to ensure no impact on university infrastructure.

Therefore, results may not fully represent behavior under **real-world internet-scale traffic conditions**.

---

## Firewall-Based Enforcement

Active defense is implemented using **dynamic rule insertion with iptables**.

The system does **not**:

- Modify kernel modules
- Implement custom kernel-level packet filtering

Kernel-level packet filtering is beyond the scope of this project.
