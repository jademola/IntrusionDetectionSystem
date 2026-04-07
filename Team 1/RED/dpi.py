import os
import sys
import socket


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


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(" Error: Missing target IP.")
        print("Usage: python3 attacker.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    
    # Run tests
   
    run_dpi_test(target_ip)