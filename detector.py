import re
from datetime import datetime
from collections import *


#constants
THRESHOLD = 5
TIME_WINDOW = 10
WHITELIST = {"127.0.0.1", "192.168.1.1"}
LOG_FILE = "Linux_2k.log"
PATTERN = re.compile(r"(\w+ +\d+ \d+:\d+:\d+).*from (\d+\.\d+\.\d+\.\d+)")


failed_attemps = defaultdict(list)

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
        
        failed_attemps[ip].append(timestamp)
        
        #detection logic
        
#print how many times each IP has failed        
for ip, timestamp in failed_attemps.items():
    print(f"{ip} has failed {len(failed_attemps[ip])} times")