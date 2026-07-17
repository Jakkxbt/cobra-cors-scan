#!/usr/bin/env python3
"""Lab target: only ever returns its own whitelisted origin, never reflects the forged one.
cors-scan must stay SILENT here (no cry-wolf). Localhost only — for testing the scanner."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ALLOWED = "https://safe.local"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def do_GET(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", ALLOWED)          # fixed whitelist, ignores forged Origin
        self.send_header("Access-Control-Allow-Credentials", "true")
        body = b"ok"
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18091)
    a = ap.parse_args()
    print(f"safe_app on http://127.0.0.1:{a.port}/  (fixed origin — expect silence)")
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
