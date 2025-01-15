from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from websocket import create_connection
import sys
import ssl
import json
import threading
import queue
import time
import uuid

# Retrieve the WebSocket server URL from command line argument
if len(sys.argv) < 2:
    print("Usage: python middleware.py wss://<target-ip-for-websocket>/")
    sys.exit(1)

ws_server = sys.argv[1]
if ws_server.startswith("ws://"):
    print("Warning: You are using an unsecured WebSocket connection.")

# Global WebSocket connection and locks
ws = None
ws_lock = threading.Lock()
response_queues = {}
response_lock = threading.Lock()

# Create a WebSocket connection
def create_shared_connection():
    global ws
    try:
        print(f"[DEBUG] Establishing WebSocket connection to {ws_server}")
        ws = create_connection(ws_server, sslopt={"cert_reqs": ssl.CERT_NONE}, timeout=30)
        print(f"[DEBUG] WebSocket connection established.")
        return ws
    except Exception as e:
        print(f"[ERROR] Failed to establish WebSocket connection: {e}")
        return None

# WebSocket reader thread
def reader_thread():
    global ws
    while True:
        try:
            response = ws.recv()
            print(f"[DEBUG] Raw WebSocket Response: {response}")
            response_data = json.loads(response)
            tracing_id = response_data.get("tracingId")

            if tracing_id:
                with response_lock:
                    if tracing_id in response_queues:
                        response_queues[tracing_id].put(response_data)
        except Exception as e:
            print(f"[ERROR] WebSocket read error: {e}")
            break

# Send periodic heartbeats to keep the connection alive
def send_heartbeat(ws):
    while True:
        with ws_lock:
            if ws and ws.connected:
                try:
                    ws.ping()
                    print("[DEBUG] Sent heartbeat to WebSocket server.")
                except Exception as e:
                    print(f"[ERROR] Heartbeat failed: {e}")
        time.sleep(30)

# Send WebSocket message and wait for a response
def send_ws(payload):
    global ws

    tracing_id = str(uuid.uuid4())
    payload = json.loads(payload)
    payload["tracingId"] = tracing_id

    with response_lock:
        response_queues[tracing_id] = queue.Queue()

    with ws_lock:
        try:
            print(f"[DEBUG] Sending payload with tracingId {tracing_id}: {json.dumps(payload)}")
            ws.send(json.dumps(payload))
        except Exception as e:
            print(f"[ERROR] WebSocket send error: {e}")
            with response_lock:
                del response_queues[tracing_id]
            return {"error": "WebSocket send failed"}

    try:
        # Wait for the response with a timeout
        response = response_queues[tracing_id].get(timeout=30)
        print(f"[DEBUG] Received response for tracingId {tracing_id}: {response}")
        return response
    except queue.Empty:
        print(f"[ERROR] No response received for tracingId {tracing_id}")
        return {"error": "No response received"}
    finally:
        with response_lock:
            del response_queues[tracing_id]

# Middleware server setup
def middleware_server(host_port):
    global ws
    ws = create_shared_connection()
    if ws:
        threading.Thread(target=reader_thread, daemon=True).start()
        threading.Thread(target=send_heartbeat, args=(ws,), daemon=True).start()

    class CustomHandler(SimpleHTTPRequestHandler):
        def do_POST(self):
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')

                # Send request and get response
                content = send_ws(post_data)

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(content).encode())
            except Exception as e:
                print(f"[ERROR] Middleware error: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f'{{"error": "{str(e)}"}}'.encode())

    class _TCPServer(TCPServer):
        allow_reuse_address = True

    httpd = _TCPServer(host_port, CustomHandler)
    httpd.serve_forever()

print("[+] Starting Middleware Server on port 8491")
try:
    middleware_server(('0.0.0.0', 8491))
except KeyboardInterrupt:
    print("[INFO] Shutting down middleware server.")
