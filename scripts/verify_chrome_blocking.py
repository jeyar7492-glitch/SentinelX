#!/usr/bin/env python3
"""
SentinelX Chrome Pre-Navigation Blocking Verification Script
Runs a local mock HTTP server and uses Chrome with --load-extension and --host-resolver-rules
to prove that blocked domains never reach the destination server.
"""

import http.server
import os
import socketserver
import subprocess
import threading
import time
import urllib.request

TEST_PORT = 9494
received_requests = []


class LoggingHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        host_header = self.headers.get("Host", "")
        received_requests.append({
            "path": self.path,
            "host": host_header,
            "client": self.client_address[0]
        })
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"DESTINATION SERVER REACHED")

    def log_message(self, format, *args):
        pass  # Suppress default noisy console logs


def run_test():
    global received_requests
    received_requests = []

    # 1. Start Mock HTTP Server on TEST_PORT
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("127.0.0.1", TEST_PORT), LoggingHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"[TEST] Mock destination server active on 127.0.0.1:{TEST_PORT}")

    extension_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "extension"))

    # 2. Test Safe / Unblocked domain first
    # Using host-resolver-rules to map safe-test-domain.test to our mock server
    cmd_safe = [
        "/opt/google/chrome/chrome",
        "--headless=new",
        f"--disable-extensions-except={extension_dir}",
        f"--load-extension={extension_dir}",
        f'--host-resolver-rules=MAP safe-test-domain.test 127.0.0.1:{TEST_PORT}',
        "--dump-dom",
        f"http://safe-test-domain.test:{TEST_PORT}/safe-probe"
    ]

    print("[TEST] Launching Chrome probe to unblocked domain: safe-test-domain.test...")
    proc_safe = subprocess.run(cmd_safe, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)

    safe_reached = any(req["host"].startswith("safe-test-domain.test") for req in received_requests)
    print(f"[TEST] Safe domain probe reached mock server: {safe_reached}")
    assert safe_reached, "Test prerequisite failed: mock server did not receive safe request"

    # Reset request log
    received_requests = []

    # 3. Test Blocked Domain: paypal-security-verification.test (In SentinelX SEED_THREAT_RULES)
    cmd_blocked = [
        "/opt/google/chrome/chrome",
        "--headless=new",
        f"--disable-extensions-except={extension_dir}",
        f"--load-extension={extension_dir}",
        f'--host-resolver-rules=MAP paypal-security-verification.test 127.0.0.1:{TEST_PORT}',
        "--dump-dom",
        f"http://paypal-security-verification.test:{TEST_PORT}/malicious-path"
    ]

    print("[TEST] Launching Chrome probe to blocked threat domain: paypal-security-verification.test...")
    proc_blocked = subprocess.run(cmd_blocked, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)

    # 4. Verification Analysis
    blocked_reached = any(req["host"].startswith("paypal-security-verification.test") for req in received_requests)
    dom_output = proc_blocked.stdout

    print("\n" + "=" * 65)
    print("  EVIDENCE OF CHROME PRE-NAVIGATION INTERCEPTION:")
    print("=" * 65)
    print(f"  Target URL: http://paypal-security-verification.test:{TEST_PORT}/malicious-path")
    print(f"  Destination Server Received Requests: {len(received_requests)} (Expected: 0)")
    print(f"  Did Blocked Request Reach Destination Server: {blocked_reached}")
    print(f"  Chrome stderr: {proc_blocked.stderr}")
    print(f"  Chrome stdout snippet: {proc_blocked.stdout[:300]}")

    is_blocked_page_rendered = "Website Blocked for Your Protection" in dom_output or "SentinelX" in dom_output
    print(f"  Rendered SentinelX Block Interstitial: {is_blocked_page_rendered}")
    print("=" * 65)

    server.shutdown()

    if not blocked_reached and is_blocked_page_rendered:
        print("\n[SUCCESS] PRE-NAVIGATION BLOCKING VERIFIED IN CHROME!")
        print("Chrome DNR redirected navigation before destination socket connection was formed.")
        return 0
    else:
        print("\n[FAILURE] Chrome request was not properly blocked.")
        return 1


if __name__ == "__main__":
    exit(run_test())
