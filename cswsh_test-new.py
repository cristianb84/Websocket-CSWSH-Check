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
    except Exception:
        print(f"[-] {unencrypted_url} does not accept unencrypted WebSocket connections.")
        return False


async def test_cswsh(target_url, skip_ssl_verify, custom_origin):
    parsed_url = urlparse(target_url)
    short_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', '', ''))

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if skip_ssl_verify:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    try:
        # Pass custom Origin header using the `origin` parameter
        async with websockets.connect(target_url, ssl=ssl_context, origin=custom_origin) as ws:
            print(f"[+] Successfully connected to {short_url}")
            print("[+] CSWSH vulnerability testing requires manual inspection of WebSocket behavior.")
    except websockets.exceptions.WebSocketException as e:
        if isinstance(e, websockets.exceptions.InvalidStatusCode):
            if e.status_code == 403:
                print(f"[-] {short_url} - 403 Forbidden - correctly rejects connections with tampered Origin. Not vulnerable to CSWSH.")
            else:
                print(f"Error: Received HTTP status {e.status_code}")
        else:
            print(f"[-] WebSocket exception: {str(e)}")
    except Exception as e:
        print(f"[-] General exception: {str(e).splitlines()[-1]}")


if __name__ == "__main__":
    display_banner()
    parser = argparse.ArgumentParser(description="Test for CSWSH vulnerability and unencrypted WebSocket communication")
    parser.add_argument("-k", "--skip-ssl", action="store_true", help="Skip SSL verification")
    parser.add_argument("-o", "--origin", default="https://malicious.com", help="Specify the custom origin (default: https://malicious.com)")
    parser.add_argument("-u", "--url", required=True, help="Specify the target WebSocket URL")

    args = parser.parse_args()

    try:
        asyncio.run(check_unencrypted_communication(args.url))
        asyncio.run(test_cswsh(args.url, args.skip_ssl, args.origin))
    except Exception as e:
        print(f"[-] Error: {str(e).splitlines()[-1]}")
