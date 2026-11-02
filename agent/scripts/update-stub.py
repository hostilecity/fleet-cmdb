#!/usr/bin/env python3
"""A stand-in for the agent API and the release channel, for scripts/update-smoke.sh (P1-AGENT-UPDATE).

    update-stub.py PORT CERT KEY DIR

DIR holds everything the test shares with the stub:

    plan.json                       what the stub does now; re-read on every request, written by the test
    events.jsonl                    what the stub saw, one JSON object per line (written by the stub)
    releases/NAME/manifest.json     a release: its manifest, the minisign signature of the manifest,
    releases/NAME/manifest.json.minisig   and the binary (the test builds and signs them with throwaway keys)
    releases/NAME/fleet-agent

plan.json (every key optional):

    "directive":  {"rollout_id": 1, "version": "1.0.1", "release": "NAME"}
                  Sent in every heartbeat response until a result for that rollout_id is accepted
                  (docs/api/README.md: the agent_update directive). The URLs point at releases/NAME.
    "min_version": "1.0.1"          inventory reports from an older agent get 426 (NFR-5); heartbeats and
                                    update results never do (P1-UPDATES, DEC-18)
    "deny_heartbeat": ["1.0.1"]     heartbeats from these agent versions get 401
    "slow_heartbeat": {"version": "1.0.1", "seconds": 6}
                                    heartbeats from that version are answered late
    "results_503": 2                the first N posts of each update result get 503

It checks no credential: the test is about the update, not about authentication.
"""
import datetime
import hashlib
import json
import os
import re
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, CERT, KEY, DIR = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
LOCK = threading.Lock()
ACCEPTED = set()  # report_ids of update results already accepted
RESULT_POSTS = {}  # report_id -> posts so far
DONE_ROLLOUTS = set()

FILES = {"manifest": "manifest.json", "signature": "manifest.json.minisig", "binary": "fleet-agent"}


def plan():
    try:
        with open(os.path.join(DIR, "plan.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def log(**event):
    event["at"] = time.time()
    with LOCK, open(os.path.join(DIR, "events.jsonl"), "a") as f:
        f.write(json.dumps(event) + "\n")


def version_tuple(text):
    return tuple(int(part) for part in re.findall(r"\d+", text.split("-")[0])[:3])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send(self, status, body, headers=None, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Request-Id", "00000000-0000-4000-8000-0000000000aa")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def error(self, status, code, message):
        self.send(status, {"error": {"code": code, "message": message, "request_id": None}})

    def do_POST(self):  # noqa: N802 (http.server naming)
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self.error(400, "invalid_json", "Not JSON.")
        agent = str(body.get("agent_version", ""))
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        current = plan()
        if self.path == "/api/v1/heartbeat":
            return self.heartbeat(current, agent, now)
        if self.path == "/api/v1/reports/inventory":
            minimum = current.get("min_version")
            if minimum and version_tuple(agent) < version_tuple(minimum):
                log(kind="inventory", agent_version=agent, status=426)
                return self.error(426, "agent_version_unsupported", f"Agent {agent} is older than the minimum {minimum}.")
            log(kind="inventory", agent_version=agent, status=200)
            return self.send(200, {"report_id": body.get("report_id"), "duplicate": False})
        if self.path == "/api/v1/update-results":
            return self.update_result(current, agent, body)
        return self.error(404, "not_found", "Not found.")

    def heartbeat(self, current, agent, now):
        slow = current.get("slow_heartbeat") or {}
        if slow.get("version") == agent:
            time.sleep(float(slow.get("seconds", 0)))
        if agent in (current.get("deny_heartbeat") or []):
            log(kind="heartbeat", agent_version=agent, status=401)
            return self.error(401, "unauthorized", "Credential rejected.")
        directives = {}
        offer = current.get("directive")
        if offer and offer["rollout_id"] not in DONE_ROLLOUTS:
            base = f"https://localhost:{PORT}/api/v1/releases/{offer['release']}"
            directives["agent_update"] = {
                "rollout_id": offer["rollout_id"],
                "version": offer["version"],
                "manifest_url": f"{base}/manifest",
                "signature_url": f"{base}/signature",
                "binary_url": f"{base}/binary",
            }
        log(kind="heartbeat", agent_version=agent, status=200, directive=bool(directives))
        self.send(200, {"server_time": now, "directives": directives})

    def update_result(self, current, agent, body):
        report_id = str(body.get("report_id"))
        with LOCK:
            RESULT_POSTS[report_id] = RESULT_POSTS.get(report_id, 0) + 1
            posts = RESULT_POSTS[report_id]
        if posts <= int(current.get("results_503", 0)):
            log(kind="result", agent_version=agent, status=503, body=body)
            return self.error(503, "unavailable", "Try again.")
        duplicate = report_id in ACCEPTED
        ACCEPTED.add(report_id)
        DONE_ROLLOUTS.add(body.get("rollout_id"))
        log(kind="result", agent_version=agent, status=200, duplicate=duplicate, body=body)
        self.send(200, {"report_id": report_id, "duplicate": duplicate})

    def do_GET(self):  # noqa: N802
        self.serve(head=False)

    def do_HEAD(self):  # noqa: N802
        self.serve(head=True)

    def serve(self, head):
        match = re.fullmatch(r"/api/v1/releases/([A-Za-z0-9._-]+)/(manifest|signature|binary)", self.path)
        if not match:
            return self.error(404, "not_found", "Not found.")
        path = os.path.join(DIR, "releases", match.group(1), FILES[match.group(2)])
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            return self.error(404, "not_found", "No such release.")
        etag = '"' + hashlib.sha256(data).hexdigest()[:32] + '"'
        status, start = 200, 0
        wanted = re.fullmatch(r"bytes=(\d+)-", self.headers.get("Range", ""))
        if wanted and self.headers.get("If-Range", etag) == etag:
            start = int(wanted.group(1))
            if start >= len(data):
                return self.send(416, b"", {"Content-Range": f"bytes */{len(data)}"})
            status = 206
        log(kind="download", file=match.group(2), release=match.group(1), status=status, start=start)
        headers = {"ETag": etag, "Accept-Ranges": "bytes"}
        if status == 206:
            headers["Content-Range"] = f"bytes {start}-{len(data) - 1}/{len(data)}"
        self.send(status, data[start:], headers, "application/octet-stream")

    def log_message(self, *args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(CERT, KEY)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
