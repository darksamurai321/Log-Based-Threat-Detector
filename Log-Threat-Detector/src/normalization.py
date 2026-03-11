import urllib.parse
import html

def normalize_payload(payload):
    """
    Decodes obfuscated payloads to reveal hidden attacks.
    Techniques: Double URL Decode, HTML Unescape, Case Normalization.
    """
    if not payload:
        return ""

    # 1. Recursive URL Decoding (Handles %255c -> %5c -> \)
    # We loop until the string stops changing to catch multi-layer encoding
    temp_payload = payload
    for _ in range(3): # Limit loops to prevent infinite stuck
        decoded = urllib.parse.unquote(temp_payload)
        if decoded == temp_payload:
            break
        temp_payload = decoded
    
    # 2. HTML Unescape (Handles &lt;script&gt; -> <script>)
    temp_payload = html.unescape(temp_payload)

    # 3. Lowercase for case-insensitive detection
    return temp_payload.lower()