from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection
import sys
import ssl
import json

# Retrieve the WebSocket server URL from command line argument
if len(sys.argv) < 2:
    print("Usage: python middleware.py wss://<target-ip-for-websocket>/")
    sys.exit(1)

ws_server = sys.argv[1]
if ws_server.startswith("ws://"):
    print("Warning: You are using an unsecured WebSocket connection.")


def send_ws(payload):
    try:
        ws = create_connection(ws_server, sslopt={"cert_reqs": ssl.CERT_NONE})
        
        print("[DEBUG] Sending WS data:", payload)  # Debug print

        ws.send(payload)

        responses = []
        while ws.connected:
            resp = ws.recv()
            responses.append(resp)
            # We assume that if the response matches your expected format, it's the one you want.
            if "R" in resp and "I" in resp:
                break

        ws.close()

        print("[DEBUG] Received WS responses:", responses)  # Debug print

        # You can return the last response (assuming that's the one you want)
        # or parse the responses list to find the desired one.
        return responses[-1] if responses else ''
    except Exception as e:
        print("[ERROR]", e)  # Print out any errors for debugging
        return str(e)


def middleware_server(host_port, content_type="application/json"):
    class CustomHandler(SimpleHTTPRequestHandler):
        def do_POST(self) -> None:
            self.send_response(200)

            # Get content length to know how much data to read
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')

            content = send_ws(post_data)

            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(content.encode())
            return

    class _TCPServer(TCPServer):
        allow_reuse_address = True

    httpd = _TCPServer(host_port, CustomHandler)
    httpd.serve_forever()


print("[+] Starting Middleware Server")
print("[+] Send payloads in http://localhost:8491/?id=*")

try:
    middleware_server(('0.0.0.0', 8491))
except KeyboardInterrupt:
    pass
