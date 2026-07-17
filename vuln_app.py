#!/usr/bin/env python3
"""Lab target: reflects ANY Origin into ACAO and sets Access-Control-Allow-Credentials.
cors-scan must report HIGH here. Localhost only — for testing the scanner."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return

    def do_GET(self):
        origin = self.headers.get("Origin")
        self.send_response(200)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)        # reflects any origin
            self.send_header("Access-Control-Allow-Credentials", "true")   # + credentials = HIGH
        body = b"ok"
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18090)
    a = ap.parse_args()
    print(f"vuln_app on http://127.0.0.1:{a.port}/  (reflects Origin + credentials — expect HIGH)")
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
