# app.py — same code runs in every Docker image (ubuntu, alpine, busybox, cleanstart)
import json
import platform
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

START_TIME = time.time()

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = json.dumps({
            "status":  "ok",
            "host":    platform.node(),
            "python":  platform.python_version(),
            "uptime":  f"{int(time.time() - START_TIME)}s",
        }).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass  # suppress request logs

if __name__ == "__main__":
    print("Listening on :3000")
    HTTPServer(("", 3000), Handler).serve_forever()
