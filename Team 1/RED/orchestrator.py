import os
import time
import sys

# --- Configuration ---
PACKET_COUNT = 4

# --- Tests / Attacks ---
def run_ping_test(target):
    print(f"-----------------------------------------")
    print(f"GOGUARD CONNECTION TEST: {target}")
    print(f"-----------------------------------------")

    # os.system runs the standard Linux ping command
    # -c specifies the number of packets
    exit_code = os.system(f"ping -c {PACKET_COUNT} {target}")

    if exit_code == 0:
        print(f"\n Success: {PACKET_COUNT} packets sent.")
        print(f"Check the Ubuntu Go terminal for {PACKET_COUNT} detections.")
    else:
        print(f"\n Error: Could not reach {target}.")
        print(f"Check your VirtualBox Host-Only adapter settings.")

# Main runpoint
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(" Error: Missing target IP.")
        print("Usage: python3 attacker.py <target_ip>")
        sys.exit(1)

    #Takes the IP from the command line input
    target_ip = sys.argv[1]
    run_ping_test(target_ip)