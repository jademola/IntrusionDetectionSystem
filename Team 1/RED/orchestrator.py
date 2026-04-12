import os
import sys
import socket
import time

# --- Configuration ---
PACKET_COUNT = 4
FLOOD_COUNT = 600  # Exceeds your 500 threshold

def run_ping_test(target):
    print(f"-----------------------------------------")
    print(f"GOGUARD CONNECTION TEST: {target}")
    print(f"-----------------------------------------")
    exit_code = os.system(f"ping -c {PACKET_COUNT} {target}")
    if exit_code == 0:
        print(f"\n Success: {PACKET_COUNT} packets sent.")
    else:
        print(f"\n Error: Could not reach {target}.")

def run_dpi_test(target):
    print(f"-----------------------------------------")
    print(f"GOGUARD DPI TEST: Sending 'SELECT' keyword")
    print(f"-----------------------------------------")
    # Use UDP to send the keyword to any port (e.g., 8888)
    message = "SELECT * FROM users;"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(message.encode(), (target, 8888))
        print(f" Sent: '{message}' to {target}:8888")
        print(" Check Ubuntu for: !!! DPI ALERT")
    finally:
        sock.close()

def run_flood_test(target):
    print(f"-----------------------------------------")
    print(f"GOGUARD FLOOD TEST: Sending {FLOOD_COUNT} packets")
    print(f"-----------------------------------------")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(" Starting flood... this may take a second.")
    try:
        for i in range(FLOOD_COUNT):
            sock.sendto(b"flood-test-packet", (target, 9999))
        print(f" Done. Sent {FLOOD_COUNT} packets.")
        print(" Check Ubuntu for: !!! TIMEOUT APPLIED")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(" Error: Missing target IP.")
        print("Usage: python3 attacker.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    
    # Run tests in sequence
    run_ping_test(target_ip)
    time.sleep(1) # Small pause between tests
    run_dpi_test(target_ip)
    time.sleep(1)
    run_flood_test(target_ip)