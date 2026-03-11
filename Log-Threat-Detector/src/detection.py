import re
import csv
import os

# --- 1. ENTERPRISE THREAT PATTERNS ---
# We use a standard dictionary for O(1) lookups.
# Expanded to include Ransomware, Miners, and Advanced CVEs.
THREAT_PATTERNS = {
    # --- Injection Attacks ---
    "SQL Injection": r"(?i)(UNION\s+SELECT|' OR '1'='1|--|;\s*DROP\s+TABLE|XP_CMDSHELL|benchmark\(|sleep\(|pg_sleep|waitfor delay)",
    "Cross-Site Scripting (XSS)": r"(?i)(<script>|javascript:|onerror=|onload=|alert\(|document\.cookie|onmouseover=|onfocus=)",
    "Command Injection (RCE)": r"(?i)(;\s*cat\s+|;\s*rm\s+|\|\s*nc\s+|`whoami`|\$\(.*\)|&&|\|\||/bin/sh|/bin/bash)",
    "Web Shell / Backdoor": r"(?i)(c99\.php|r57\.php|cmd\.asp|shell\.aspx|eval\(base64_decode|system\()",
    
    # --- File System Attacks ---
    "Path Traversal": r"(?i)(\.\./|\.\.\\|/etc/passwd|c:\\windows\\system32|boot\.ini|\.\./\.\./)",
    "Local File Inclusion (LFI)": r"(?i)(\.\./\.\./|%2e%2e%2f|/etc/passwd|/proc/self/environ)",
    
    # --- Modern Enterprise Threats (NEW) ---
    "Cryptominer Activity": r"(?i)(xmrig|monero|minerd|stratum\+tcp|cryptonight|coinhive)",
    "Ransomware Artifact": r"(?i)(\.encrypt$|\.lock$|\.ryuk$|\.wannacry|\.crypt$|restore_files\.txt|readme_decrypt\.txt)",
    
    # --- Critical CVEs ---
    "Shellshock (CVE-2014-6271)": r"(?i)\(\)\s*\{\s*:;\s*\}\s*;",
    "Log4j (CVE-2021-44228)": r"(?i)(\$\{jndi:ldap|\$\{jndi:rmi|\$\{jndi:dns)",
    
    # --- Reconnaissance ---
    "Scanner/Bot Agent": r"(?i)(sqlmap|nikto|nmap|masscan|python-requests|curl|wget|burpcollaborator|acunetix|nessus)",
    "Credential Stuffing": r"(?i)(login|signin|admin|auth).*(fail|error|incorrect|invalid|denied)",
    
    # --- Evasion Techniques ---
    "Double Encoding": r"(?i)(%255c|%252e|%252f)",
    "Base64/Hex Payload": r"([A-Za-z0-9+/]{40,}={0,2}|\\x[0-9A-Fa-f]{2,})"
}

# --- 2. THREAT INTELLIGENCE (IOC Loader) ---
# Loads the CSV into memory for high-speed lookups
MALICIOUS_IPS = {}
csv_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'malicious_ips.csv')

if os.path.exists(csv_path):
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Store IP and Risk Level (default to High if missing)
                if 'ip_address' in row:
                    MALICIOUS_IPS[row['ip_address']] = row.get('risk_level', 'High')
        print(f"[*] Threat Intelligence Loaded: {len(MALICIOUS_IPS)} IPs")
    except Exception as e:
        print(f"[-] Warning: Could not load Threat Intel CSV: {e}")
else:
    print(f"[-] Note: No 'malicious_ips.csv' found. Running in Rule-Only mode.")

# --- 3. DETECTION LOGIC ---
def detect_threats(payload, ip_address):
    """
    Checks a normalized payload against Regex rules AND checks IP against IOC list.
    Designed to be thread-safe for Load Balancing.
    """
    detected_threats = []

    # Check 1: Threat Intelligence (IOC) - O(1) Lookup
    if ip_address in MALICIOUS_IPS:
        risk = MALICIOUS_IPS[ip_address]
        detected_threats.append(f"KNOWN MALICIOUS IP (Risk: {risk})")

    # Check 2: Regex Patterns
    for threat_name, pattern in THREAT_PATTERNS.items():
        if re.search(pattern, payload):
            detected_threats.append(threat_name)

    return detected_threats