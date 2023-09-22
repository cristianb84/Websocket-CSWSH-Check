import asyncio
import ssl
import websockets
import argparse

async def test_cswsh(target_url, skip_ssl_verify, custom_origin):
    headers = {
        "Origin": custom_origin,
        # ... Any other headers you'd like to set
    }

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if skip_ssl_verify:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    try:
        async with websockets.connect(target_url, extra_headers=headers, ssl=ssl_context) as ws:
            # Get the response headers from the server
            response_headers = ws.response_headers

            # Check for the presence of the Access-Control headers
            acao_header = response_headers.get("Access-Control-Allow-Origin")
            acab_header = response_headers.get("Access-Control-Allow-Credentials")
            
            if acao_header == custom_origin and acab_header == "true":
                print(f"[+] {target_url} is vulnerable to CSWSH!")
            else:
                print(f"[-] {target_url} is not vulnerable to CSWSH.")
    except Exception as e:
        # Only display the last line of the error
        print(str(e).splitlines()[-1])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test for CSWSH vulnerability")
    parser.add_argument("-k", "--skip-ssl", action="store_true", help="Skip SSL verification")
    parser.add_argument("-o", "--origin", default="https://malicious.com", help="Specify the custom origin (default: https://malicious.com)")
    parser.add_argument("-u", "--url", required=True, help="Specify the target WebSocket URL")

    args = parser.parse_args()

    try:
        asyncio.get_event_loop().run_until_complete(test_cswsh(args.url, args.skip_ssl, args.origin))
    except Exception as e:
        # Only display the last line of the errors
        print(str(e).splitlines()[-1])
