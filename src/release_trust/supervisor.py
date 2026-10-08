#!/usr/bin/env python3
"""Small platform-owned supervisor used for deterministic admission restarts."""

import json
import os
import signal
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.RLock()
CHILD = None


def _spawn():
    global CHILD
    with LOCK:
        if CHILD is not None and CHILD.poll() is None:
            return CHILD.pid
        CHILD = subprocess.Popen(
            [
                "uvicorn",
                "release_trust.admission:app",
                "--app-dir",
                "/workspace/src",
                "--host",
                "0.0.0.0",
                "--port",
                "8081",
                "--reload",
                "--reload-dir",
                "/workspace/src/release_trust",
            ],
            cwd="/workspace",
            start_new_session=True,
        )
        return CHILD.pid


def _kill():
    global CHILD
    with LOCK:
        if CHILD is None or CHILD.poll() is not None:
            CHILD = None
            return False
        os.killpg(CHILD.pid, signal.SIGKILL)
        CHILD.wait(timeout=10)
        CHILD = None
        return True


def _status():
    with LOCK:
        running = CHILD is not None and CHILD.poll() is None
        return {"running": running, "pid": CHILD.pid if running else None}


class Handler(BaseHTTPRequestHandler):
    def _reply(self, status, value):
        body = json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/status":
            self._reply(404, {"error": "not found"})
            return
        self._reply(200, _status())

    def do_POST(self):
        if self.path == "/kill":
            self._reply(200, {"killed": _kill(), **_status()})
        elif self.path == "/start":
            self._reply(200, {"started": True, "pid": _spawn()})
        else:
            self._reply(404, {"error": "not found"})

    def log_message(self, _format, *_args):
        return


def main():
    _spawn()
    server = ThreadingHTTPServer(("0.0.0.0", 8091), Handler)
    try:
        server.serve_forever()
    finally:
        _kill()


if __name__ == "__main__":
    main()
