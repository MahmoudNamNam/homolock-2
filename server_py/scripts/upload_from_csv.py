#!/usr/bin/env python3
"""
Upload session from CSV or JSON (no static data): read data/employees.csv or
data/employees.json, encrypt with CLI, then POST session/keys, session/data,
and employees/from-batch so List Employees returns your rows.

Run from server_py:
  python -m scripts.upload_from_csv --csv ../data/employees.csv
  python -m scripts.upload_from_csv --json ../data/employees.json
  python -m scripts.upload_from_csv   # uses data/employees.csv or data/employees.json if present

Requires: PySEAL (for CLI), requests. Server must be running.
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import subprocess
import sys
import uuid
from pathlib import Path

try:
    import requests
except ImportError:
    print("pip install requests", file=sys.stderr)
    sys.exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent
SERVER_PY = SCRIPT_DIR.parent
REPO_ROOT = SERVER_PY.parent
OUT_DIR = SERVER_PY / "out"
DATA_DIR = REPO_ROOT / "data"


def resolve_data_file(csv_path: str | None, json_path: str | None) -> tuple[Path, str]:
    """Return (path, "csv"|"json"). Prefer explicit --json/--csv; else default to data/employees.json or data/employees.csv."""
    def resolve(p: Path) -> Path:
        if p.is_absolute():
            return p
        for base in [Path.cwd(), REPO_ROOT, DATA_DIR]:
            cand = (base / p) if base != DATA_DIR else (base / p.name)
            if cand.exists():
                return cand.resolve()
        return (Path.cwd() / p).resolve()

    if json_path is not None:
        return resolve(Path(json_path)), "json"
    if csv_path is not None:
        return resolve(Path(csv_path)), "csv"
    for name, kind in [("employees.json", "json"), ("employees.csv", "csv")]:
        for base in [DATA_DIR, REPO_ROOT, Path.cwd()]:
            cand = (base / "data" / name) if base != DATA_DIR else (base / name)
            if cand.exists():
                return cand.resolve(), kind
    return DATA_DIR / "employees.csv", "csv"


def load_employee_ids(path: Path, kind: str) -> list[str]:
    """Load ordered employee_ids from CSV or JSON."""
    if kind == "csv":
        with open(path, newline="") as f:
            return [r["employee_id"].strip() for r in csv.DictReader(f) if r.get("employee_id", "").strip()]
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        raise ValueError("JSON must be an array of objects")
    return [str(item["employee_id"]).strip() for item in data if item.get("employee_id")]


def run_cli(*args: str, cwd: Path) -> None:
    cmd = [sys.executable, "-m", "client.cli"] + list(args)
    env = {"PYTHONPATH": str(cwd)}
    r = subprocess.run(cmd, cwd=str(cwd), env={**__import__("os").environ, **env}, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr or r.stdout, file=sys.stderr)
        raise SystemExit(r.returncode)


def main():
    ap = argparse.ArgumentParser(description="Upload session from CSV or JSON via API (no static data)")
    ap.add_argument("--csv", type=str, default=None, help="Path to employees.csv")
    ap.add_argument("--json", type=str, default=None, help="Path to employees.json (array of {employee_id, salary_cents, hours, bonus_points})")
    ap.add_argument("--server", type=str, default="http://localhost:8000", help="Server base URL")
    ap.add_argument("--session-id", type=str, default=None, help="Session ID (default: run-<random>)")
    args = ap.parse_args()

    data_path, kind = resolve_data_file(args.csv, args.json)
    if not data_path.exists():
        print(f"File not found: {data_path}", file=sys.stderr)
        sys.exit(1)

    session_id = args.session_id or f"run-{uuid.uuid4().hex[:12]}"
    base = args.server.rstrip("/")

    print(f"Reading {kind.upper()} and encrypting (CLI)...")
    run_cli("init-context", cwd=SERVER_PY)
    run_cli("keygen", cwd=SERVER_PY)
    if kind == "json":
        run_cli("encrypt-hr", "--json", str(data_path), cwd=SERVER_PY)
    else:
        run_cli("encrypt-hr", "--csv", str(data_path), cwd=SERVER_PY)

    # Build payloads from out/
    params_b64 = base64.b64encode((OUT_DIR / "params.seal").read_bytes()).decode("ascii")
    pk_b64 = base64.b64encode((OUT_DIR / "public_key.seal").read_bytes()).decode("ascii")
    relin_b64 = base64.b64encode((OUT_DIR / "relin_keys.seal").read_bytes()).decode("ascii")
    payload_keys = {"session_id": session_id, "params_b64": params_b64, "public_key_b64": pk_b64, "relin_keys_b64": relin_b64}
    if (OUT_DIR / "galois_keys.seal").exists():
        payload_keys["galois_keys_b64"] = base64.b64encode((OUT_DIR / "galois_keys.seal").read_bytes()).decode("ascii")

    salary_b64 = base64.b64encode((OUT_DIR / "salary.ct").read_bytes()).decode("ascii")
    hours_b64 = base64.b64encode((OUT_DIR / "hours.ct").read_bytes()).decode("ascii")
    bonus_b64 = base64.b64encode((OUT_DIR / "bonus_points.ct").read_bytes()).decode("ascii")
    meta = json.loads((OUT_DIR / "meta.json").read_text())
    count = meta.get("count", 0)
    payload_data = {"session_id": session_id, "salary_ct_b64": salary_b64, "hours_ct_b64": hours_b64, "bonus_points_ct_b64": bonus_b64, "count": count}

    employee_ids = load_employee_ids(data_path, kind)
    if len(employee_ids) != count:
        print(f"Warning: {kind} has {len(employee_ids)} rows, meta count is {count}. Using file order.", file=sys.stderr)

    print("Uploading session keys...")
    r = requests.post(f"{base}/v1/session/keys", json=payload_keys, timeout=60)
    r.raise_for_status()

    print("Uploading session data...")
    r = requests.post(f"{base}/v1/session/data", json=payload_data, timeout=120)
    r.raise_for_status()

    print("Creating employees from batch...")
    r = requests.post(f"{base}/v1/session/{session_id}/employees/from-batch", json={"employee_ids": employee_ids}, timeout=60)
    r.raise_for_status()

    print(f"Done. session_id = {session_id}")
    print(f"  List Employees: GET {base}/v1/session/{session_id}/employees")
    print(f"  In Postman: set collection variable session_id = {session_id}")


if __name__ == "__main__":
    main()
