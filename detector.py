import re
from datetime import datetime
from collections import *


#constants
THRESHOLD = 5
TIME_WINDOW = 10
WHITELIST = {"127.0.0.1", "192.168.1.1"}
LOG_FILE = "Linux_2k.log"
PATTERN = re.compile(r"(\w+ +\d+ \d+:\d+:\d+).*from (\d+\.\d+\.\d+\.\d+)")


failed_attempts = defaultdict(list)
blocked_ips = set()

#logic for parsing and extracting IP and datetime
with open(LOG_FILE, "r") as f:
    for line in f:
        if "Failed password" not in line:
            continue
        
        match = PATTERN.search(line)
        if not match:
            continue
        
        timestamp_str = match.group(1)
        ip = match.group(2)
        
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
        timestamp = timestamp.replace(year=datetime.now().year)
        
        failed_attempts[ip].append(timestamp)
        
for ip, timestamp in failed_attempts.items():
    if len(failed_attempts[ip]) >= THRESHOLD:
        if ip in WHITELIST:
            continue
        elif ip in blocked_ips:
            continue
        
        blocked_ips.add(ip)
        
print("\n--- Summary ---")
print(f"Unique IPs with failed attempts: {len(failed_attempts)}")
print(f"IPs blocked: {len(blocked_ips)}")

if blocked_ips:
    print("\nBlocked IPs:")
    for ip in blocked_ips:
        print(f"{ip} - {len(failed_attempts)} failed attempts ")
else:
    print("No IPs were blocked")