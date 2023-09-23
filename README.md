CSWSH Vulnerability Checker
This Python script is designed to test targets for Cross-Site WebSocket Hijacking (CSWSH) vulnerabilities. By manipulating the Origin header in WebSocket handshake requests, it checks if a WebSocket server improperly validates this header, potentially leading to security risks.

Requirements
Python 3.x
websockets library
argparse library (usually installed with Python by default)
You can install the required Python packages using pip:
pip install websockets

Usage:
python cswsh_test.py -u <target_url> [-o <origin_url>] [-k]

Arguments:

-u, --url: The target WebSocket URL.
-o, --origin: Optional. Set a custom Origin header value. Default is https://malicious.com.
-k, --skip-ssl-verify: Optional. Skip SSL certificate verification. Useful for targets with self-signed certificates.

Example:
python cswsh_test.py -u "wss://example.com/socket" -o "https://attacker.com" -k

This command will target wss://example.com/socket with a fake Origin of https://attacker.com, and it will skip SSL certificate verification.


Results
Upon execution, the script will display whether the target is vulnerable to CSWSH based on the presence of specific headers in the response. If the script detects the vulnerability, it will provide the request and response details for further analysis.
