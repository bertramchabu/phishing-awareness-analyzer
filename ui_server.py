"""Local web interface for the synthetic-email phishing analyzer."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from phishing_analyzer import analyze_email


ROOT = Path(__file__).resolve().parent
SAMPLE_NAMES = {"legit_01.eml", "phishing_01.eml"}
MAX_EMAIL_BYTES = 1_048_576
HOST = "127.0.0.1"
PORT = 8000


class AnalyzerHandler(BaseHTTPRequestHandler):
    def _send(self, status: int, content_type: str, content: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'none'",
        )
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, status: int, payload: dict) -> None:
        content = json.dumps(payload).encode("utf-8")
        self._send(status, "application/json; charset=utf-8", content)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        assets = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/style.css": ("style.css", "text/css; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        }
        if path in assets:
            filename, content_type = assets[path]
            self._send(200, content_type, (ROOT / "ui" / filename).read_bytes())
            return

        prefix = "/samples/"
        sample_name = path.removeprefix(prefix) if path.startswith(prefix) else ""
        if sample_name in SAMPLE_NAMES and "/" not in sample_name:
            self._send(
                200,
                "message/rfc822",
                (ROOT / "samples" / sample_name).read_bytes(),
            )
            return

        self._send_json(404, {"error": "Not found."})

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/analyze":
            self._send_json(404, {"error": "Not found."})
            return

        if self.headers.get_content_type() != "application/octet-stream":
            self._send_json(415, {"error": "Upload an .eml file to analyze."})
            return

        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send_json(400, {"error": "A valid Content-Length is required."})
            return

        if content_length <= 0:
            self._send_json(400, {"error": "The selected file is empty."})
            return
        if content_length > MAX_EMAIL_BYTES:
            self._send_json(413, {"error": "Files must be 1 MB or smaller."})
            return

        email_bytes = self.rfile.read(content_length)
        if len(email_bytes) != content_length:
            self._send_json(400, {"error": "The upload was incomplete."})
            return

        result = analyze_email(email_bytes)
        self._send_json(200, result)

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.address_string()} - {format % args}")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), AnalyzerHandler)
    print(f"Phishing Awareness Analyzer running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
