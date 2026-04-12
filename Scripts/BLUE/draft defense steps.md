Part 1: Flow Tracking Data Structures (main.go:39-65)

FlowKey struct  →  identifies a TCP connection by 4 things:
  {SrcIP, DstIP, SrcPort, DstPort}
FlowBuffer struct  →  stores the accumulated payload + last activity time
tcpFlows map  →  global dictionary: FlowKey → FlowBuffer
maxKeywordLen  →  length of longest keyword ("SELECT" = 6) 
                  used for the sliding window size
Why: When packet 1 arrives with "SEL" and packet 2 arrives with "ECT", we need a place to store both so we can combine them.
Part 2: reassembleAndInspectTCP() (main.go:224-279)
Step-by-step:
1. Extract TCP layer from packet
2. Build a FlowKey from (srcIP, dstIP, srcPort, dstPort)
3. Look up this flow in tcpFlows map
4. If not found → create new FlowBuffer
5. Append packet payload to the buffer
6. Take last N bytes of buffer (N = longest keyword length)
7. Check those bytes against all danger keywords
8. If found → BAN and delete the flow
The sliding window trick: Instead of checking the entire buffer (which grows forever), we only check the last N bytes. When "SEL" arrives, buffer = "SEL" (6 chars), window = "SEL" → no match. When "ECT * FROM users;" arrives, buffer = "SELECT * FROM users;", window = last 20 chars → contains "SELECT" → BAN.
Part 3: cleanupFlows() (main.go:281-291)
Removes flows idle for >30 seconds to prevent memory exhaustion.
Part 4: Main Loop Change (main.go:456-460)
BEFORE: processDPI(packet, src, f)        → checks individual packet
AFTER:  reassembleAndInspectTCP(packet, src, dstIP, f)  → checks combined buffer

---

How to Test
Step 1: On Ubuntu — Start the Defense
cd "IntrusionDetectionSystem/Team 1/BLUE"
sudo go run main.go dashboard.go -iface enp0s8

You should see:
GoGuard IPS: Defender Node is starting...
GoGuard: Monitoring enp0s8. Waiting for packets...


Step 2: On Kali — Run the Fragmentation Attack
cd "IntrusionDetectionSystem/Team 1/RED"
python3 frag_attack.py
Edit frag_attack.py first if needed — change target_ip to your Ubuntu IP:
target_ip = "192.168.56.102"  # ← change to YOUR Ubuntu IP


Step 3: On Ubuntu — Watch for Detection
Before the fix, you'd see packets logged but no ban.
After the fix, you should see:
!!! DPI ALERT (reassembled): Keyword 'SELECT' detected from 192.168.56.101
!!! DPI_THREAT detected from 192.168.56.101: 1 attempts. KERNEL BLOCK APPLIED.


Step 4: Verify the Ban Works
On Ubuntu, check iptables:
sudo iptables -L INPUT -n
You should see:
DROP  all  --  192.168.56.101  0.0.0.0/0
On Kali, try pinging Ubuntu — it should fail (packet dropped):
ping -c 2 <UBUNTU_IP>
After 60 seconds, the ban auto-expires and ping works again.
