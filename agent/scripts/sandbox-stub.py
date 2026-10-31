#!/usr/bin/env python3
"""A minimal HTTPS stand-in for the agent API, for scripts/sandbox-smoke.sh (P1-PACKAGING, review of #72).

    sandbox-stub.py PORT CERT KEY OUT_DIR

Accepts every heartbeat (empty directives, ADR 0020) and every inventory report, and saves the last body
of each to OUT_DIR/heartbeat.json and OUT_DIR/inventory.json. Anything else gets the API's 404 envelope.
It checks nothing: the smoke test is about what the agent can do inside its sandbox, not the API.
"""
import datetime
import json
import os
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, CERT, KEY, OUT = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Request-Id", "00000000-0000-4000-8000-0000000000aa")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):  # noqa: N802 (http.server naming)
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if self.path == "/api/v1/heartbeat":
            self.save("heartbeat.json", body)
            self.reply(200, {"server_time": now, "directives": {}})
        elif self.path == "/api/v1/reports/inventory":
            self.save("inventory.json", body)
            self.reply(200, {"report_id": body.get("report_id"), "duplicate": False})
        else:
            self.reply(404, {"error": {"code": "not_found", "message": "Not found.", "request_id": None}})

    def save(self, name, body):
        path = os.path.join(OUT, name)
        with open(path + ".tmp", "w") as f:
            json.dump(body, f)
        os.replace(path + ".tmp", path)

    def log_message(self, *args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(CERT, KEY)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
