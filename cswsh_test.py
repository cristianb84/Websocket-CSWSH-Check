import asyncio
import ssl
import websockets
import argparse
from urllib.parse import urlparse, urlunparse

def display_banner():
    print(r"""
 __          __  _     _____            _        _   
 \ \        / / | |   / ____|          | |      | |  
  \ \  /\  / /__| |__| (___   ___   ___| | _____| |_ 
   \ \/  \/ / _ \ '_ \\___ \ / _ \ / __| |/ / _ \ __|
    \  /\  /  __/ |_) |___) | (_) | (__|   <  __/ |_ 
     \/  \/ \___|_.__/_____/ \___/ \___|_|\_\___|\__|
    """)
    print("WebSocket Security Tester\n")


async def check_unencrypted_communication(target_url):
    parsed_url = urlparse(target_url)
    short_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))
    
    if short_url.startswith("wss"):
        unencrypted_url = "ws" + short_url[3:]
    else:
        unencrypted_url = short_url

    try:
        async with websockets.connect(unencrypted_url) as ws:
            print(f"[+] {unencrypted_url} accepts unencrypted WebSocket connections!")
            return True
    except Exception as e:
        print(f"[-] {unencrypted_url} does not accept unencrypted WebSocket connections.")
        return False

async def test_cswsh(target_url, skip_ssl_verify, custom_origin):
    headers = {
        "Origin": custom_origin,
    }

    parsed_url = urlparse(target_url)
    short_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if skip_ssl_verify:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    try:
        async with websockets.connect(target_url, extra_headers=headers, ssl=ssl_context) as ws:
            response_headers = ws.response_headers

            acao_header = response_headers.get("Access-Control-Allow-Origin")
            acab_header = response_headers.get("Access-Control-Allow-Credentials")

            if acao_header == custom_origin and acab_header == "true":
                print(f"[+] {short_url} is vulnerable to CSWSH!")
            else:
                print(f"[-] {short_url} is not vulnerable to CSWSH.")
    except websockets.exceptions.InvalidStatusCode as e:
        if e.status_code == 403:
            print(f"[-] {short_url} - 403 Forbidden - correctly rejects connections with tampered Origin. Not vulnerable to CSWSH.")
        else:
            print(f"Error: Received HTTP status {e.status_code}")

    except Exception as e:
        print(str(e).splitlines()[-1])

if __name__ == "__main__":
    display_banner()
    parser = argparse.ArgumentParser(description="Test for CSWSH vulnerability and unencrypted WebSocket communication")
    parser.add_argument("-k", "--skip-ssl", action="store_true", help="Skip SSL verification")
    parser.add_argument("-o", "--origin", default="https://malicious.com", help="Specify the custom origin (default: https://malicious.com)")
    parser.add_argument("-u", "--url", required=True, help="Specify the target WebSocket URL")

    args = parser.parse_args()

    try:
        asyncio.get_event_loop().run_until_complete(check_unencrypted_communication(args.url))
        asyncio.get_event_loop().run_until_complete(test_cswsh(args.url, args.skip_ssl, args.origin))
    except Exception as e:
        print(str(e).splitlines()[-1])
