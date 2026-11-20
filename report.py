"""
Reads honeypot_log.jsonl and prints a simple summary.

Run:   python3 report.py
"""

import ipaddress
import json
import urllib.request
from collections import Counter
from datetime import datetime

LOG_FILE = "honeypot_log.jsonl"

# Remember answers so we don't ask about the same IP twice
location_cache = {}


def get_location(ip):
    """Return a short text like 'Paris, France' for an IP address."""
    if ip in location_cache:
        return location_cache[ip]

    # IPs from your own computer or home network have no public location
    if ipaddress.ip_address(ip).is_private:
        place = "your own computer / local network"
    else:
        try:
            # Free lookup service (no sign-up needed)
            url = f"http://ip-api.com/json/{ip}?fields=status,country,city"
            with urllib.request.urlopen(url, timeout=5) as response:
                info = json.load(response)
            if info.get("status") == "success":
                place = f"{info['city']}, {info['country']}"
            else:
                place = "unknown location"
        except Exception:
            place = "location lookup failed"

    location_cache[ip] = place
    return place


def load_attempts():
    attempts = []
    try:
        with open(LOG_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    attempts.append(json.loads(line))
    except FileNotFoundError:
        pass
    return attempts


# Passwords and usernames that attackers try first
COMMON_PASSWORDS = {"123456", "password", "admin", "letmein", "qwerty",
                    "12345678", "123456789", "111111", "welcome", "abc123"}
COMMON_USERNAMES = {"admin", "root", "test", "user", "administrator", "guest"}


def summarize(attempts):
    """Write a short plain-English summary using simple rules."""
    total = len(attempts)
    points = 0     # more points = more dangerous
    lines = []

    # Rule 1: how many tries, and from how many IPs
    ip_counts = Counter(a["ip"] for a in attempts)
    top_ip, top_count = ip_counts.most_common(1)[0]
    lines.append(f"There were {total} login attempts from {len(ip_counts)} IP address(es).")

    # Rule 2: one IP tried again and again
    if top_count >= 5:
        points += 1
        lines.append(f"{top_ip} ({get_location(top_ip)}) tried {top_count} times. "
                     "Repeated guessing from one place is a warning sign.")

    # Rule 3: speed. Humans are slow, bots are fast.
    times = sorted(datetime.fromisoformat(a["time"]) for a in attempts)
    seconds = (times[-1] - times[0]).total_seconds()
    if total >= 5 and seconds <= 60:
        points += 2
        lines.append(f"All of it happened in {max(int(seconds), 1)} second(s). "
                     "That is too fast for a person, so it was probably a bot.")

    # Rule 4: very common passwords
    weak = sum(1 for a in attempts if a["password"].lower() in COMMON_PASSWORDS)
    if weak * 2 >= total:
        points += 1
        lines.append(f"{weak} of {total} passwords were very common ones "
                     "(like 123456). Attackers try these first.")

    # Rule 5: very common usernames
    common = sum(1 for a in attempts if a["username"].lower() in COMMON_USERNAMES)
    if common * 2 >= total:
        points += 1
        lines.append(f"{common} of {total} usernames were common ones "
                     "(like admin or root).")

    # Final answer: how worried should we be?
    if points >= 4:
        level = "HIGH"
    elif points >= 2:
        level = "MEDIUM"
    else:
        level = "LOW"
    lines.append(f"Risk level: {level}.")
    return lines


def print_top(title, items, how_many=5):
    print(f"\n{title}")
    for value, count in Counter(items).most_common(how_many):
        print(f"  {count:>3}  {value}")


def main():
    attempts = load_attempts()
    if not attempts:
        print("No login attempts yet.")
        return

    print(f"Total login attempts: {len(attempts)}")
    print(f"First attempt: {attempts[0]['time']}")
    print(f"Last attempt:  {attempts[-1]['time']}")

    print("\nTop IP addresses")
    for ip, count in Counter(a["ip"] for a in attempts).most_common(5):
        print(f"  {count:>3}  {ip}  ({get_location(ip)})")
    print_top("Top usernames tried", [a["username"] for a in attempts])
    print_top("Top passwords tried", [a["password"] for a in attempts])

    print("\nSUMMARY")
    for line in summarize(attempts):
        print(f"  - {line}")


if __name__ == "__main__":
    main()
