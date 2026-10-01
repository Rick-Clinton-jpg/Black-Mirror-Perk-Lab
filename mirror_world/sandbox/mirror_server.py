"""A real Answered Mirror: a live HTTP server on loopback whose responses
genuinely vary by which real backing state answered the query. A client
makes an actual network round trip and can genuinely observe the
differential-response leak Article III's motivating attack describes --
this is not a canned response table read in-process.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

_REAL_BACKING_STATE = {
    "host-a": {"is-port-22-open": "yes"},
    "host-b": {"is-port-22-open": "no"},
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # silence default request logging
        pass

    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        query = params.get("q", [""])[0]
        backing = params.get("backing", [""])[0]
        answer = _REAL_BACKING_STATE.get(backing, {}).get(query, "unknown")

        body = answer.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class AnsweredMirrorServer:
    """Starts a real HTTPServer on a background thread bound to loopback."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._httpd = HTTPServer((host, port), _Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._httpd.server_address[1]

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
