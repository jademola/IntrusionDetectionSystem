from scapy.all import IP, TCP, Raw, send
import time

# Configuration
target_ip = "192.168.56.102"
target_port = 22
src_ip = "192.168.56.101"

print(f"--- Starting Packet Splitting Attack on {target_ip} ---")

# 1. The first half: "SEL"
# We manually set the Sequence Number (seq) to keep the stream aligned
packet1 = IP(src=src_ip, dst=target_ip) / \
          TCP(sport=12345, dport=target_port, flags="PA", seq=1000) / \
          Raw(load="SEL")

# 2. The second half: "ECT * FROM users;"
packet2 = IP(src=src_ip, dst=target_ip) / \
          TCP(sport=12345, dport=target_port, flags="PA", seq=1003) / \
          Raw(load="ECT * FROM users;")

print("Sending Fragment 1: 'SEL'...")
send(packet1)

# Small delay to ensure they arrive as distinct packets in the Go buffer
time.sleep(0.5)

print("Sending Fragment 2: 'ECT * FROM users;'...")
send(packet2)

print("--- Attack Complete. Check GoGuard for 'DPI_THREAT' ---")