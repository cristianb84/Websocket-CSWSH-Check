from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection, WebSocketConnectionClosedException
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

# Global WebSocket connection
ws = None


def create_ws_connection():
    global ws
    try:
        ws = create_connection(
            ws_server,
            sslopt={
                "cert_reqs": ssl.CERT_NONE,
                "ssl_version": ssl.PROTOCOL_TLSv1_2,  # specify TLS version explicitly
                "check_hostname": False
            }
        )
    except Exception as e:
        print("[ERROR] Couldn't establish WebSocket connection:", str(e))
        sys.exit(1)


# Create the WebSocket connection at the start
create_ws_connection()


def send_ws(payload):
    global ws
    try:
        print("[DEBUG] Sending WS data:", payload)

        # Check if connection is closed and reconnect if necessary
        if not ws.connected:
            print("[DEBUG] Reconnecting WebSocket...")
            create_ws_connection()

        ws.send(payload)

        responses = []
        while ws.connected:
            resp = ws.recv()
            responses.append(resp)
            if ("R" in resp or "E" in resp) and "I" in resp:
            	break

        print("[DEBUG] Received WS responses:", responses)
        return responses[-1] if responses else ''
    except WebSocketConnectionClosedException:
        print("[DEBUG] WebSocket connection closed, attempting to reconnect...")
        create_ws_connection()
        return send_ws(payload)  # Recursive call after reconnection
    except Exception as e:
        print("[ERROR]", e)
        return str(e)


def middleware_server(host_port, content_type="application/json"):
    class CustomHandler(SimpleHTTPRequestHandler):
        def do_POST(self) -> None:
            self.send_response(200)
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
