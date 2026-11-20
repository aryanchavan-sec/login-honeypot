"""
Simple login honeypot.

It shows a FAKE admin login page. Nobody real should ever use it,
so any login attempt is suspicious. Every attempt is saved to a log file.

Run:   python3 honeypot.py
Then open: http://localhost:8080
"""

import json
import os
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

# By default only your own computer can reach it (safe for testing).
# On the cloud server we start it with HONEYPOT_HOST=0.0.0.0 so the internet can reach it.
HOST = os.environ.get("HONEYPOT_HOST", "127.0.0.1")
PORT = 8080
LOG_FILE = "honeypot_log.jsonl"

LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head><title>Admin Portal</title></head>
<body style="font-family: sans-serif; max-width: 320px; margin: 80px auto;">
  <h2>Admin Portal</h2>
  <p style="color:red;">{message}</p>
  <form method="POST" action="/login">
    <p><input name="username" placeholder="Username"></p>
    <p><input name="password" type="password" placeholder="Password"></p>
    <p><button type="submit">Log in</button></p>
  </form>
</body>
</html>
"""


def save_attempt(ip, username, password, user_agent):
    """Write one login attempt to the log file (one JSON line per attempt)."""
    entry = {
        "time": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "username": username,
        "password": password,
        "user_agent": user_agent,
    }
    with log_lock:   # only one visitor writes to the log at a time
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    print(f"[!] Login attempt from {ip}: user={username!r} password={password!r}")


log_lock = threading.Lock()


class HoneypotHandler(BaseHTTPRequestHandler):
    # Hang up on anyone who connects and then says nothing for 10 seconds.
    # Without this, one silent visitor can block everyone else.
    timeout = 10

    def send_page(self, message=""):
        body = LOGIN_PAGE.format(message=message).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Any page request shows the fake login page
        self.send_page()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = parse_qs(self.rfile.read(length).decode(errors="replace"))
        username = data.get("username", [""])[0][:100]   # cut long input
        password = data.get("password", [""])[0][:100]
        save_attempt(
            ip=self.client_address[0],
            username=username,
            password=password,
            user_agent=self.headers.get("User-Agent", ""),
        )
        # Always say it failed, so attackers keep guessing
        self.send_page("Invalid username or password.")

    def log_message(self, format, *args):
        pass  # turn off the default noisy logging


if __name__ == "__main__":
    # ThreadingHTTPServer talks to many visitors at the same time
    server = ThreadingHTTPServer((HOST, PORT), HoneypotHandler)
    print(f"Honeypot running at http://{HOST}:{PORT}  (press Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
