#!/usr/bin/env python3

import os
import socket

def test_read_shadow():
    """Attempt to read /etc/shadow."""
    print("=== Test: Reading /etc/shadow ===")
    try:
        with open("/etc/shadow", "r") as f:
            data = f.read()
        print("[FAIL] Read /etc/shadow successfully (unexpected if sandboxed).")
    except Exception as e:
        print(f"[OK] Failed to read /etc/shadow: {e}")

def test_write_root():
    """Attempt to write to /root/testfile."""
    print("=== Test: Writing /root/testfile ===")
    try:
        with open("/root/testfile", "w") as f:
            f.write("Hello from the sandbox test.\n")
        print("[FAIL] Wrote to /root/testfile successfully (unexpected if sandboxed).")
    except Exception as e:
        print(f"[OK] Failed to write /root/testfile: {e}")

def test_tcp_connect():
    """Attempt to connect to localhost:80."""
    print("=== Test: TCP connect to localhost:80 ===")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 80))
        s.sendall(b"GET / HTTP/1.1\r\n\r\n")
        response = s.recv(1024)
        s.close()
        print("[FAIL] Managed to connect and send data on port 80 (unexpected if sandboxed).")
    except Exception as e:
        print(f"[OK] Failed to connect or send data on port 80: {e}")

def main():
    print("===== Sandbox Test Script =====\n")
    test_read_shadow()
    print()
    test_write_root()
    print()
    test_tcp_connect()
    print("\n===== Test Completed =====")

if __name__ == "__main__":
    main()
