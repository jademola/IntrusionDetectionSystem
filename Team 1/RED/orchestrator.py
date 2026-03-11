import os
import time

# --- Configuration ---
# Change this to your Ubuntu enp0s8 IP
TARGET_IP = "192.168.1.x"
PACKET_COUNT = 4

# --- Tests / Attacks ---
def run_ping_test():
    print(f"-----------------------------------------")
    print(f"GOGUARD CONNECTION TEST: {TARGET_IP}")
    print(f"-----------------------------------------")

    # os.system runs the standard Linux ping command
    # -c specifies the number of packets
    exit_code = os.system(f"ping -c {PACKET_COUNT} {TARGET_IP}")

    if exit_code == 0:
        print(f"\n Success: {PACKET_COUNT} packets sent.")
        print(f"Check the Ubuntu Go terminal for {PACKET_COUNT} detections.")
    else:
        print(f"\n Error: Could not reach {TARGET_IP}.")
        print(f"Check your VirtualBox Host-Only adapter settings.")

# Main runpoint
if __name__ == "__main__":
    try:
        run_ping_test()
    except KeyboardInterrupt:
        print("\nTest aborted by user.")