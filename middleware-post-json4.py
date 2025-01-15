from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection
import sys
import ssl
import json
import threading
import time

# Retrieve the WebSocket server URL from command line argument
if len(sys.argv) < 2:
    print("Usage: python middleware.py wss://<target-ip-for-websocket>/")
    sys.exit(1)

ws_server = sys.argv[1]
if ws_server.startswith("ws://"):
    print("Warning: You are using an unsecured WebSocket connection.")

# Create a persistent WebSocket connection
def create_persistent_connection():
    try:
        print(f"[DEBUG] Establishing persistent connection to WebSocket server: {ws_server}")
        ws = create_connection(ws_server, sslopt={"cert_reqs": ssl.CERT_NONE}, timeout=10)
        print(f"[DEBUG] Persistent WebSocket connection established.")
        return ws
    except Exception as e:
        print(f"[ERROR] Failed to establish WebSocket connection: {e}")
        return None

# Re-establish the WebSocket connection if it's inactive
def ensure_connection(ws):
    if not ws or not ws.connected:
        print("[INFO] Reconnecting WebSocket...")
        return create_persistent_connection()
    return ws

# Send periodic heartbeats to keep the connection alive
def send_heartbeat(ws):
    while True:
        if ws and ws.connected:
            try:
                ws.ping()
                print("[DEBUG] Sent heartbeat to WebSocket server.")
            except Exception as e:
                print(f"[ERROR] Heartbeat failed: {e}")
        time.sleep(30)  # Send heartbeat every 30 seconds

# Use the persistent connection for sending messages
def send_ws_persistent(ws, payload):
    try:
        ws = ensure_connection(ws)
        if not ws:
            return '{"error":"Failed to reconnect to WebSocket server"}'

        print(f"[DEBUG] Sending WS data: {payload}")
        ws.send(payload)

        responses = []
        while ws.connected:
            try:
                resp = ws.recv()
                print(f"[DEBUG] Received response: {resp}")
                responses.append(resp)
                break  # Assume single response per request
            except Exception as e:
                print(f"[ERROR] Error receiving WebSocket response: {e}")
                break

        return responses[-1] if responses else '{"error":"No valid response received"}'
    except Exception as e:
        print(f"[ERROR] WebSocket interaction failed: {e}")
        return f'{{"error": "{str(e)}"}}'

def middleware_server(host_port, content_type="application/json"):
    ws = create_persistent_connection()

    # Start a heartbeat thread
    threading.Thread(target=send_heartbeat, args=(ws,), daemon=True).start()

    class CustomHandler(SimpleHTTPRequestHandler):
        def do_POST(self) -> None:
            try:
                self.send_response(200)
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')

                content = send_ws_persistent(ws, post_data)

                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(content.encode())
            except BrokenPipeError:
                print("[ERROR] Client disconnected before response could be sent.")
            except Exception as e:
                print(f"[ERROR] Middleware error: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f'{{"error": "{str(e)}"}}'.encode())

    class _TCPServer(TCPServer):
        allow_reuse_address = True

    httpd = _TCPServer(host_port, CustomHandler)
    httpd.serve_forever()

print("[+] Starting Middleware Server")
print("[+] Send payloads in http://localhost:8491/?id=*")

try:
    middleware_server(('0.0.0.0', 8491))
except KeyboardInterrupt:
    print("[INFO] Shutting down middleware server.")
