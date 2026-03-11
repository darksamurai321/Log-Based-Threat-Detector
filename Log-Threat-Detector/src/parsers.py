import re

# 1. Standard Apache/Combined Log Pattern (The Industry Standard)
# Matches: 127.0.0.1 - - [10/Oct/2000...] "GET /index.html" 200
APACHE_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+\['  # IP Address
    r'(?P<time>.*?)\]\s+'                             # Timestamp
    r'"(?P<request>.*?)"\s+'                          # Request Line
    r'(?P<status>\d{3})'                              # Status Code
)

# 2. Custom Login Log Pattern (Your Specific Requirement)
# Matches: 200 OK 12.55.22.88 jr22 2019-03-18...
CUSTOM_LOGIN_PATTERN = re.compile(
    r'(?P<status>\d{3})\s+\w+\s+'                     # Status (e.g., 200 OK)
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'             # IP Address
    r'(?P<user>\S+)\s+'                               # Username
    r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+' # ISO Timestamp
    r'(?P<request>/\S*)'                              # Request Path
)

def parse_log_line(line):
    """
    Tries multiple regex patterns to extract data from a log line.
    Designed for High Performance (Fail fast if empty).
    Returns: dict with 'ip', 'time', 'request', 'status' OR None
    """
    # Performance Optimization: Skip empty lines immediately
    if not line or len(line) < 10:
        return None

    line = line.strip()

    # Strategy 1: Try Apache Format (Most Common)
    match = APACHE_PATTERN.search(line)
    if match:
        data = match.groupdict()
        # Ensure we return a dictionary with consistent keys
        return {
            'ip': data.get('ip'),
            'time': data.get('time'),
            'request': data.get('request'),
            'status': data.get('status'),
            'ua': data.get('ua', '-') # Default to dash if missing
        }

    # Strategy 2: Try Custom Login Format (Your custom logs)
    match = CUSTOM_LOGIN_PATTERN.search(line)
    if match:
        data = match.groupdict()
        return {
            'ip': data.get('ip'),
            'time': data.get('time'),
            'request': data.get('request'),
            'status': data.get('status'),
            'ua': '-' # Custom logs don't have UA, so we add a placeholder
        }

    # Fallback: Return None (Skip corrupt lines without crashing)
    return None