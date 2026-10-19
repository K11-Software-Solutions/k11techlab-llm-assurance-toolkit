"""Serve a demo bot over HTTP so you can try the ``http`` target type.

    python examples/serve_demo_bot.py            # vulnerable bot on :8000
    python examples/serve_demo_bot.py --hardened # hardened bot

POST /chat  {"message": "...", "history": [...]}  ->  {"reply": "..."}
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from demo_bots import hardened_respond, vulnerable_respond


def make_handler(respond):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            if self.path != "/chat":
                self.send_error(404)
                return
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            history = body.get("history") or []
            messages = history + [{"role": "user", "content": body.get("message", "")}]
            payload = json.dumps({"reply": respond(messages)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    return Handler


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--hardened", action="store_true")
    args = ap.parse_args()
    respond = hardened_respond if args.hardened else vulnerable_respond
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(respond))
    print(f"Demo bot ({'hardened' if args.hardened else 'vulnerable'}) on http://127.0.0.1:{args.port}/chat")
    server.serve_forever()


if __name__ == "__main__":
    main()
