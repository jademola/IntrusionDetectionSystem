
import sys
import socket

FLOOD_COUNT = 600  # Exceeds your 500 threshold


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
    
    # Run tests
   
    run_flood_test(target_ip)