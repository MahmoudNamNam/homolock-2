#!/usr/bin/env python3
"""
Local helper for Postman: serves session-keys and session-data JSON from out/ so
Postman can auto-fill the Session Keys (and Session Data) request bodies.

Run from server_py:
  python -m scripts.serve_postman_keys
  # or: python -m scripts.serve_postman_keys --port 9999

Then in Postman, the "Session Keys" request has a pre-request script that fetches
from http://localhost:9999/session-keys-json and sets the body automatically.
"""
from __future__ import annotations

import argparse
import base64
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# When run as python -m scripts.serve_postman_keys, cwd is often server_py
OUT_DIR = Path.cwd() / "out"


def session_keys_payload(session_id: str) -> dict:
    out = OUT_DIR
    for name in ["params.seal", "public_key.seal", "relin_keys.seal"]:
        if not (out / name).exists():
            raise FileNotFoundError(f"Missing {out}/{name}. Run: init-context then keygen")
    payload = {
        "session_id": session_id,
        "params_b64": base64.b64encode((out / "params.seal").read_bytes()).decode("ascii"),
        "public_key_b64": base64.b64encode((out / "public_key.seal").read_bytes()).decode("ascii"),
        "relin_keys_b64": base64.b64encode((out / "relin_keys.seal").read_bytes()).decode("ascii"),
    }
    if (out / "galois_keys.seal").exists():
        payload["galois_keys_b64"] = base64.b64encode((out / "galois_keys.seal").read_bytes()).decode("ascii")
    return payload


def session_data_payload(session_id: str) -> dict:
    out = OUT_DIR
    for name in ["salary.ct", "hours.ct", "bonus_points.ct", "meta.json"]:
        if not (out / name).exists():
            raise FileNotFoundError(f"Missing {out}/{name}. Run: encrypt-hr")
    meta = json.loads((out / "meta.json").read_text())
    return {
        "session_id": session_id,
        "salary_ct_b64": base64.b64encode((out / "salary.ct").read_bytes()).decode("ascii"),
        "hours_ct_b64": base64.b64encode((out / "hours.ct").read_bytes()).decode("ascii"),
        "bonus_points_ct_b64": base64.b64encode((out / "bonus_points.ct").read_bytes()).decode("ascii"),
        "count": meta.get("count", 0),
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)
        session_id = (qs.get("session_id") or ["my-session"])[0]

        try:
            if path == "/session-keys-json":
                body = session_keys_payload(session_id)
            elif path == "/session-data-json":
                body = session_data_payload(session_id)
            else:
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"Not found. Use /session-keys-json or /session-data-json"}')
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode("utf-8"))
        except FileNotFoundError as e:
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

    def log_message(self, format, *args):
        print(f"[serve_postman_keys] {args[0]}")


def main():
    ap = argparse.ArgumentParser(description="Serve session-keys/session-data JSON for Postman from out/")
    ap.add_argument("--port", type=int, default=9999, help="Port (default 9999)")
    args = ap.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Serving session-keys and session-data JSON at http://127.0.0.1:{args.port}")
    print("  GET /session-keys-json?session_id=my-session")
    print("  GET /session-data-json?session_id=my-session")
    print("Run from server_py with out/ present. Ctrl+C to stop.")
    server.serve_forever()


if __name__ == "__main__":
    main()
