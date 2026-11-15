#!/usr/bin/env python3
"""
A protocol-3 control plane for testing the image without a real plane.

WHAT: the five node endpoints the agent calls (`enroll`, `heartbeat`,
`config`, `certs`, `report`) plus `action` and `stats`, served from one
directory of files:

    <state-dir>/token        bearer token, no trailing newline
    <state-dir>/node         node id, one line
    <state-dir>/state.json   {"desired": {"hash","config"} | null,
                              "certs": {"etag","certs": [...]} | null,
                              "actions": [{"action","version"?}, ...]}

    state.json is re-read per request, so changing a phase is one `cp` or one
    `python3 -c` — no restart, no reseed.

WHY it exists: the real plane's admin API is behind Cloudflare Access, so a
plane-authored config cannot be produced from CI or from a shell. This stub
answers the same shapes as `LessV/src/routers/node.ts`, so the image can be
driven through apply, certificate sync, rollback, recreate and update on any
host, with zero external dependencies.

WHY not just `wrangler dev`: both are useful and they test different things.
`wrangler dev` gives the plane's own renderer (see LessV docs/dev/testing.md);
this gives deterministic phases and no Cloudflare account. Neither replaces a
real node on a real host.

NOT a product: development tool, binds 127.0.0.1 by default, no TLS, no
persistence guarantees, one node at a time.

Usage:
    python3 scripts/dev_stub_plane.py --state-dir /tmp/plane [--port 8080]
"""

import argparse
import json
import os
import sys
import threading
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE_DIR = "."
LOCK = threading.Lock()


def read_control(name, default=None):
    path = os.path.join(STATE_DIR, name)
    if not os.path.exists(path):
        return default
    with open(path, "rb") as handle:
        return handle.read()


def read_state():
    raw = read_control("state.json", b"{}")
    try:
        return json.loads(raw or b"{}")
    except ValueError:
        return {}


def log(line):
    sys.stderr.write(line + "\n")
    sys.stderr.flush()


def append_log(name, payload):
    with LOCK, open(os.path.join(STATE_DIR, name), "ab") as handle:
        handle.write(payload.encode() + b"\n")


def empty_manifest():
    """WHAT: the etag the plane returns for "no certificates".

    WHY this exact value: it is the sha256 of the empty string in the same
    quoted-hex form LessV's `manifestEtag` produces, so the node's ETag
    comparison behaves exactly as it does against the real plane.
    """
    return {"etag": '"%s"' % sha256(b"").hexdigest(), "certs": []}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # the journal is the log
        pass

    def send_json(self, status, payload, headers=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            return {}

    def authorised(self):
        token = (read_control("token", b"") or b"").decode().strip()
        node = (read_control("node", b"") or b"").decode().strip()
        presented = self.headers.get("Authorization", "")
        presented = presented.split(" ", 1)[1].strip() if " " in presented else ""
        return (
            bool(token)
            and presented == token
            and self.headers.get("X-Lessv-Node") == node
        )

    def require_auth(self):
        if self.authorised():
            return True
        self.send_json(401, {"detail": "invalid node credentials"})
        return False

    def do_POST(self):
        if not self.require_auth():
            return
        path = self.path.split("?", 1)[0]
        payload = self.body()
        state = read_state()
        if path == "/api/node/enroll":
            log("enroll " + json.dumps(payload))
            desired = state.get("desired") or {}
            self.send_json(
                200,
                {
                    "id": (read_control("node", b"") or b"").decode().strip(),
                    "label": "stub",
                    "address": "",
                    "state": "active",
                    "desired_hash": desired.get("hash"),
                },
            )
            return
        if path == "/api/node/heartbeat":
            append_log("heartbeats.log", json.dumps(payload))
            desired = state.get("desired") or {}
            self.send_json(
                200,
                {
                    "desired_hash": desired.get("hash"),
                    "actions": state.get("actions") or [],
                },
            )
            return
        if path == "/api/node/report":
            append_log("reports.log", json.dumps(payload))
            self.send_json(200, {})
            return
        if path == "/api/node/action":
            append_log("actions.log", json.dumps(payload))
            self.send_json(200, {})
            return
        if path == "/api/node/stats":
            counters = payload.get("counters") or {}
            self.send_json(200, {"accepted": len(counters)})
            return
        self.send_json(404, {"detail": "Not found"})

    def do_GET(self):
        if not self.require_auth():
            return
        path, _, query = self.path.partition("?")
        params = dict(part.split("=", 1) for part in query.split("&") if "=" in part)
        state = read_state()
        if path == "/api/node/config":
            desired = state.get("desired")
            if not desired:
                self.send_json(404, {"detail": "no renderable config"})
                return
            if params.get("hash") not in (None, desired["hash"]):
                self.send_json(
                    409,
                    {
                        "detail": "desired config moved; re-heartbeat",
                        "desired_hash": desired["hash"],
                    },
                )
                return
            self.send_json(
                200,
                {"hash": desired["hash"], "config": desired["config"]},
                {"Cache-Control": "no-store"},
            )
            return
        if path == "/api/node/certs":
            manifest = state.get("certs") or empty_manifest()
            if self.headers.get("If-None-Match") == manifest["etag"]:
                self.send_response(304)
                self.send_header("ETag", manifest["etag"])
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_json(
                200, manifest, {"ETag": manifest["etag"], "Cache-Control": "no-store"}
            )
            return
        self.send_json(404, {"detail": "Not found"})


def main():
    global STATE_DIR
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--state-dir", default=".", help="directory holding token/node/state.json")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    STATE_DIR = os.path.abspath(args.state_dir)
    os.makedirs(STATE_DIR, exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    log(f"stub plane on {args.host}:{args.port}, state in {STATE_DIR}")
    server.serve_forever()


if __name__ == "__main__":
    main()