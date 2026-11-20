# Login Honeypot

A fake admin login page that records break-in attempts, plus a report that explains them in plain English.

## What it does
- Logs the time, IP address, username, password tried, and device for every attempt
- Finds the country and city of each IP address
- Gives a simple summary and a risk level (low, medium, high)
- Runs on a cloud server (Microsoft Azure, Linux)

## Files
- honeypot.py: the fake login page and logger
- report.py: reads the log and prints the report

## How to run
python3 honeypot.py
python3 report.py

## Note
Passwords in the logs are from attackers, so the log file is not included here.
