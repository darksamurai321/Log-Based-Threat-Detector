import random
import time
import os
from datetime import datetime, timedelta

# --- CONFIGURATION ---
# Robust Path Fixing: accurately finds 'data' folder relative to this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data")
OUTPUT_FILE = os.path.join(DATA_DIR, "generated_traffic.log")

NUM_LINES = 500  # How many logs to generate
ATTACK_RATIO = 0.2  # 20% of traffic will be malicious

# --- DATA POOLS ---
SAFE_IPS = ["192.168.1.5", "10.0.0.2", "172.16.0.55", "192.168.1.102", "10.10.10.5"]
BAD_IPS = ["14.14.14.14", "23.23.23.23", "49.99.13.16", "103.20.10.5", "185.100.20.1"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Googlebot/2.1 (+http://www.google.com/bot.html)"
]

SAFE_URLS = [
    "/index.php", "/about.html", "/contact", "/products?id=1", 
    "/images/logo.png", "/css/style.css", "/js/main.js", "/login"
]

ATTACK_PAYLOADS = [
    "/index.php?id=1 UNION SELECT username, password FROM users", # SQLi
    "/search?q=<script>alert('Hacked')</script>", # XSS
    "/download?file=../../../../etc/passwd", # Path Traversal
    "/login?user=admin&pass=' OR '1'='1", # SQLi
    "/api?cmd=;cat /etc/shadow", # Command Injection
    "/misc?data=%255c%255c..%255c%255cwindows", # Double Encoding (Normalization Test)
    "/api?payload=eyJmb28iOiJhYmMifQ==" # Base64
]

def generate_log_line():
    is_attack = random.random() < ATTACK_RATIO
    
    if is_attack and random.random() < 0.5:
        ip = random.choice(BAD_IPS)
    else:
        ip = random.choice(SAFE_IPS)

    delta = random.randint(0, 86400)
    ts = datetime.now() - timedelta(seconds=delta)
    ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")

    if is_attack:
        request = f"GET {random.choice(ATTACK_PAYLOADS)} HTTP/1.1"
        status = random.choice([200, 403, 500])
    else:
        request = f"GET {random.choice(SAFE_URLS)} HTTP/1.1"
        status = random.choice([200, 301, 304])

    size = random.randint(100, 5000)
    ua = random.choice(USER_AGENTS)

    return f'{ip} - - [{ts_str}] "{request}" {status} {size} "-" "{ua}"'

if __name__ == "__main__":
    # Ensure data directory exists
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        
    print(f"[*] Generating {NUM_LINES} log lines to {OUTPUT_FILE}...")
    try:
        with open(OUTPUT_FILE, "w") as f:
            for _ in range(NUM_LINES):
                f.write(generate_log_line() + "\n")
        print("[+] Done! Load 'data/generated_traffic.log' into your tool.")
    except Exception as e:
        print(f"[-] Error: {e}")