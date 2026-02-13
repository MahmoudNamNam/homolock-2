#!/usr/bin/env python3
"""
HomoLock-HR Python CLI client.
Uses PySEAL (seal package) when available for encrypt/decrypt; otherwise only HTTP operations.
CRUD: employee create, list, get, delete.
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import struct
import sys
import tempfile
import time
import uuid
from pathlib import Path

import numpy as np
try:
    import requests
except ImportError:
    requests = None

_SEAL = None
try:
    import seal
    _SEAL = seal
except ImportError:
    pass

OUT_DIR = Path("out")
DATA_DIR = Path("data")
DEFAULT_SERVER = "http://127.0.0.1:8000"


def _need_requests():
    if requests is None:
        print("pip install requests", file=sys.stderr)
        sys.exit(1)


def _raise_for_status(r):
    """Call r.raise_for_status(); on error print response body (server detail) to stderr."""
    if r.ok:
        return
    try:
        err = r.json()
        detail = err.get("detail", r.text)
        print(f"Server response: {detail}", file=sys.stderr)
    except Exception:
        print(r.text or r.reason, file=sys.stderr)
    r.raise_for_status()


def _need_seal():
    if _SEAL is None:
        print("PySEAL (seal) is not installed. Install it for encrypt/decrypt (e.g. pip install seal or Huelse/SEAL-Python).", file=sys.stderr)
        sys.exit(1)


def _session_id() -> str:
    return str(uuid.uuid4())[:8]


# ---------- SEAL helpers ----------

def _load_context(out_dir: Path):
    _need_seal()
    params = _SEAL.EncryptionParameters(_SEAL.scheme_type.bfv)
    params.load(str(out_dir / "params.seal"))
    ctx = _SEAL.SEALContext(params)
    err_fn = getattr(ctx, "parameter_error_message", None)
    if callable(err_fn):
        err = err_fn()
        if err and str(err).strip() and str(err) != "valid":
            raise RuntimeError(f"Invalid parameters: {err}")
    return ctx


def _save_ct_vec(path: Path, ct_bytes_list: list[bytes]) -> None:
    """Write format [count: u32][len: u32][ct bytes]..."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(struct.pack("<I", len(ct_bytes_list)))
        for b in ct_bytes_list:
            f.write(struct.pack("<I", len(b)))
            f.write(b)


def _encrypt_one(ctx, public_key, value: int) -> bytes:
    """Encrypt single uint64; return ct bytes (save to buffer then read)."""
    enc = _SEAL.Encryptor(ctx, public_key)
    batch = _SEAL.BatchEncoder(ctx)
    # BatchEncoder.encode() expects numpy int64 array and returns Plaintext
    pt = batch.encode(np.array([value], dtype=np.int64))
    # Encryptor.encrypt(plaintext) returns Ciphertext
    ct = enc.encrypt(pt)
    with tempfile.NamedTemporaryFile(suffix=".ct", delete=True) as t:
        ct.save(t.name)
        return Path(t.name).read_bytes()


# ---------- Commands ----------

def cmd_init_context(args):
    """Create params.seal (poly 4096 or 8192)."""
    _need_seal()
    poly = getattr(args, "poly", 8192)
    # SEAL-Python: scheme_type.bfv (lowercase), CoeffModulus.BFVDefault, PlainModulus.Batching
    parms = _SEAL.EncryptionParameters(_SEAL.scheme_type.bfv)
    parms.set_poly_modulus_degree(poly)
    parms.set_coeff_modulus(_SEAL.CoeffModulus.BFVDefault(poly))
    parms.set_plain_modulus(_SEAL.PlainModulus.Batching(poly, 20))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    parms.save(str(OUT_DIR / "params.seal"))
    print(f"Written {OUT_DIR}/params.seal (poly={poly})")


def cmd_keygen(args):
    """Generate secret/public/relin keys under out/."""
    _need_seal()
    ctx = _load_context(OUT_DIR)
    keygen = _SEAL.KeyGenerator(ctx)
    sk = keygen.secret_key()
    pk = keygen.create_public_key()
    rk = keygen.create_relin_keys()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sk.save(str(OUT_DIR / "secret_key.seal"))
    pk.save(str(OUT_DIR / "public_key.seal"))
    rk.save(str(OUT_DIR / "relin_keys.seal"))
    try:
        gk = keygen.create_galois_keys()
        gk.save(str(OUT_DIR / "galois_keys.seal"))
    except Exception:
        pass
    print("Written out/secret_key.seal, public_key.seal, relin_keys.seal. Never upload secret_key.seal.")


def _resolve_data_path(path: str | Path | None, default_name: str) -> Path:
    """Resolve path: cwd first, then repo root."""
    path = Path(path) if path else (Path.cwd() / DATA_DIR / default_name)
    if path.exists():
        return path.resolve()
    repo_root = Path(__file__).resolve().parent.parent.parent
    alt = repo_root / path
    if alt.exists():
        return alt.resolve()
    return path


def _load_employee_rows_csv(path: Path) -> list[dict]:
    """Load employee rows from CSV. Keys: employee_id, salary_cents, hours, bonus_points."""
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if not (r.get("employee_id") or str(r.get("employee_id", "")).strip()):
                continue
            rows.append({
                "employee_id": str(r["employee_id"]).strip(),
                "salary_cents": int(r["salary_cents"]),
                "hours": int(r["hours"]),
                "bonus_points": int(r["bonus_points"]),
            })
    return rows


def _load_employee_rows_json(path: Path) -> list[dict]:
    """Load employee rows from JSON array. Each item: employee_id, salary_cents, hours, bonus_points."""
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        raise ValueError("JSON must be an array of objects")
    rows = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Row {i}: expected object, got {type(item).__name__}")
        eid = item.get("employee_id")
        if eid is None or str(eid).strip() == "":
            continue
        rows.append({
            "employee_id": str(eid).strip(),
            "salary_cents": int(item["salary_cents"]),
            "hours": int(item["hours"]),
            "bonus_points": int(item["bonus_points"]),
        })
    return rows


def cmd_encrypt_hr(args):
    """Read employees from CSV or JSON; write out/salary.ct, hours.ct, bonus_points.ct, meta.json. Use --csv or --json."""
    _need_seal()
    csv_path = getattr(args, "csv", None)
    json_path = getattr(args, "json", None)
    if json_path is not None:
        path = _resolve_data_path(json_path, "employees.json")
        if not path.exists():
            print(f"File not found: {path}", file=sys.stderr)
            sys.exit(1)
        rows = _load_employee_rows_json(path)
        source = "JSON"
    else:
        path = _resolve_data_path(csv_path or DATA_DIR / "employees.csv", "employees.csv")
        if not path.exists():
            print(f"File not found: {path}", file=sys.stderr)
            sys.exit(1)
        rows = _load_employee_rows_csv(path)
        source = "CSV"
    ctx = _load_context(OUT_DIR)
    pk = _SEAL.PublicKey()
    pk.load(ctx, str(OUT_DIR / "public_key.seal"))
    salaries = [r["salary_cents"] for r in rows]
    hours = [r["hours"] for r in rows]
    bonus_pts = [r["bonus_points"] for r in rows]
    salary_cts = [_encrypt_one(ctx, pk, v) for v in salaries]
    hours_cts = [_encrypt_one(ctx, pk, v) for v in hours]
    bonus_cts = [_encrypt_one(ctx, pk, v) for v in bonus_pts]
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    _save_ct_vec(OUT_DIR / "salary.ct", salary_cts)
    _save_ct_vec(OUT_DIR / "hours.ct", hours_cts)
    _save_ct_vec(OUT_DIR / "bonus_points.ct", bonus_cts)
    meta = {"count": len(rows), "version": 1}
    (OUT_DIR / "meta.json").write_text(json.dumps(meta))
    print(f"Written out/salary.ct, out/hours.ct, out/bonus_points.ct, out/meta.json ({len(rows)} rows from {source})")


def _session_keys_payload(session_id: str) -> dict:
    """Build the Session Keys request body from out/*.seal. Raises if files missing."""
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


def cmd_export_session_keys(args):
    """Print Session Keys request body (JSON) for Postman. Run from server_py with out/ present."""
    session_id = getattr(args, "session_id", None) or _session_id()
    try:
        payload = _session_keys_payload(session_id)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    print(json.dumps(payload, indent=2))
    print("Copy the JSON above into Postman → Session Keys → Body (raw JSON).", file=sys.stderr)


def cmd_upload_session(args):
    _need_requests()
    base = getattr(args, "server", DEFAULT_SERVER).rstrip("/")
    session_id = getattr(args, "session_id", None) or _session_id()
    try:
        payload = _session_keys_payload(session_id)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    r = requests.post(f"{base}/v1/session/keys", json=payload, timeout=30)
    _raise_for_status(r)
    print(f"Session keys uploaded. session_id={session_id}")


def cmd_upload_data(args):
    _need_requests()
    session_id = getattr(args, "session_id", None)
    if not session_id:
        print("--session-id required", file=sys.stderr)
        sys.exit(1)
    base = getattr(args, "server", DEFAULT_SERVER).rstrip("/")
    salary_b64 = base64.b64encode((OUT_DIR / "salary.ct").read_bytes()).decode("ascii")
    hours_b64 = base64.b64encode((OUT_DIR / "hours.ct").read_bytes()).decode("ascii")
    bonus_b64 = base64.b64encode((OUT_DIR / "bonus_points.ct").read_bytes()).decode("ascii")
    meta = json.loads((OUT_DIR / "meta.json").read_text())
    count = meta.get("count", 0)
    r = requests.post(f"{base}/v1/session/data", json={
        "session_id": session_id,
        "salary_ct_b64": salary_b64,
        "hours_ct_b64": hours_b64,
        "bonus_points_ct_b64": bonus_b64,
        "count": count,
    }, timeout=60)
    _raise_for_status(r)
    print("Data uploaded.")


def cmd_compute(args):
    _need_requests()
    session_id = getattr(args, "session_id", None)
    if not session_id:
        print("--session-id required", file=sys.stderr)
        sys.exit(1)
    base = getattr(args, "server", DEFAULT_SERVER).rstrip("/")
    bonus_bps = getattr(args, "bonus_bps", 1000)
    job_ids = {}
    for op, body in [
        ("total_payroll", {"session_id": session_id}),
        ("avg_salary", {"session_id": session_id}),
        ("total_hours", {"session_id": session_id}),
        ("bonus_pool", {"session_id": session_id, "bonus_rate_bps": bonus_bps}),
    ]:
        r = requests.post(f"{base}/v1/compute/{op}", json=body, timeout=30)
        _raise_for_status(r)
        j = r.json()
        job_ids[op] = j["job_id"]
        print(f"{op}: job_id={j['job_id']}")
    return job_ids


def cmd_fetch_decrypt(args):
    _need_requests()
    _need_seal()
    job_id = getattr(args, "job_id", None)
    if not job_id:
        print("--job-id required", file=sys.stderr)
        sys.exit(1)
    base = getattr(args, "server", DEFAULT_SERVER).rstrip("/")
    r = requests.get(f"{base}/v1/result/{job_id}", timeout=30)
    _raise_for_status(r)
    data = r.json()
    if data.get("status") != "done":
        print(f"Job not done: {data.get('status')}", file=sys.stderr)
        sys.exit(1)
    ct_b64 = data.get("result_ciphertext_b64")
    if not ct_b64:
        print("No result ciphertext", file=sys.stderr)
        sys.exit(1)
    ctx = _load_context(OUT_DIR)
    sk = _SEAL.SecretKey()
    sk.load(ctx, str(OUT_DIR / "secret_key.seal"))
    dec = _SEAL.Decryptor(ctx, sk)
    batch = _SEAL.BatchEncoder(ctx)
    ct = _SEAL.Ciphertext()
    raw = base64.b64decode(ct_b64)
    with tempfile.NamedTemporaryFile(suffix=".ct", delete=True) as t:
        Path(t.name).write_bytes(raw)
        ct.load(ctx, t.name)
    # Decryptor.decrypt(ciphertext) returns Plaintext
    pt = dec.decrypt(ct)
    vals = batch.decode_int64(pt)
    value = int(vals[0]) if vals else 0
    result_type = data.get("result_type", "")
    count = data.get("count")
    bonus_bps = data.get("bonus_rate_bps")
    if result_type == "avg_salary" and count:
        print(f"sum={value}, count={count}, avg={value // count}")
    elif result_type == "bonus_pool" and bonus_bps is not None:
        pool = value * bonus_bps // 10000
        print(f"sum={value}, bonus_rate_bps={bonus_bps}, bonus_pool={pool}")
    else:
        print(value)


def cmd_run(args):
    """One-command flow: init-context → keygen → encrypt-hr → upload → compute → fetch-decrypt (all four results)."""
    session_id = getattr(args, "session_id", None) or f"run-{int(time.time())}"
    server = getattr(args, "server", DEFAULT_SERVER)
    # Build a minimal args object for each step
    class RunArgs:
        pass
    run_args = RunArgs()
    run_args.server = server
    run_args.session_id = session_id
    run_args.csv = getattr(args, "csv", None)
    run_args.poly = getattr(args, "poly", 8192)
    run_args.bonus_bps = getattr(args, "bonus_bps", 1000)
    run_args.no_decrypt = getattr(args, "no_decrypt", False)

    steps = [
        ("init-context", lambda: cmd_init_context(run_args)),
        ("keygen", lambda: cmd_keygen(run_args)),
        ("encrypt-hr", lambda: cmd_encrypt_hr(run_args)),
        ("upload-session", lambda: cmd_upload_session(run_args)),
        ("upload-data", lambda: cmd_upload_data(run_args)),
    ]
    for name, step in steps:
        try:
            step()
        except Exception as e:
            print(f"run failed at {name}: {e}", file=sys.stderr)
            sys.exit(1)

    print(f"\nSession: {session_id}")
    try:
        job_ids = cmd_compute(run_args)
    except Exception as e:
        print(f"run failed at compute: {e}", file=sys.stderr)
        sys.exit(1)

    if run_args.no_decrypt:
        print("\nJob IDs (use fetch-decrypt --job-id <id> to get results):")
        for op, jid in job_ids.items():
            print(f"  {op}: {jid}")
        return

    print("\n--- Results ---")
    for label, result_type in [
        ("Total payroll", "total_payroll"),
        ("Avg salary", "avg_salary"),
        ("Total hours", "total_hours"),
        ("Bonus pool", "bonus_pool"),
    ]:
        jid = job_ids.get(result_type)
        if not jid:
            continue
        run_args.job_id = jid
        try:
            print(f"{label}: ", end="")
            cmd_fetch_decrypt(run_args)
        except Exception as e:
            print(f"{label}: failed - {e}", file=sys.stderr)


# ---------- CRUD employee ----------

def cmd_employee_create(args):
    """Create or replace one employee. Requires seal and pre-encrypted values or use --from-csv-row."""
    _need_requests()
    session_id = getattr(args, "session_id", None)
    employee_id = getattr(args, "employee_id", None)
    if not session_id or not employee_id:
        print("--session-id and --employee-id required", file=sys.stderr)
        sys.exit(1)
    base = getattr(args, "server", DEFAULT_SERVER).rstrip("/")
    if getattr(args, "from_csv", None):
        _need_seal()
        csv_path = getattr(args, "csv", None) or DATA_DIR / "employees.csv"
        row = None
        with open(csv_path, newline="") as f:
            for r in csv.DictReader(f):
                if r["employee_id"].strip() == employee_id:
                    row = r
                    break
        if not row:
            print(f"Employee {employee_id} not in {csv_path}", file=sys.stderr)
            sys.exit(1)
        ctx = _load_context(OUT_DIR)
        pk = _SEAL.PublicKey()
        pk.load(ctx, str(OUT_DIR / "public_key.seal"))
        salary_b64 = base64.b64encode(_encrypt_one(ctx, pk, int(row["salary_cents"]))).decode("ascii")
        hours_b64 = base64.b64encode(_encrypt_one(ctx, pk, int(row["hours"]))).decode("ascii")
        bonus_b64 = base64.b64encode(_encrypt_one(ctx, pk, int(row["bonus_points"]))).decode("ascii")
    else:
        salary_b64 = getattr(args, "salary_ct_b64", None)
        hours_b64 = getattr(args, "hours_ct_b64", None)
        bonus_b64 = getattr(args, "bonus_points_ct_b64", None)
        if not all([salary_b64, hours_b64, bonus_b64]):
            print("Either --from-csv or provide salary_ct_b64, hours_ct_b64, bonus_points_ct_b64", file=sys.stderr)
            sys.exit(1)
    r = requests.post(f"{base}/v1/session/{session_id}/employees", json={
        "employee_id": employee_id,
        "salary_ct_b64": salary_b64,
        "hours_ct_b64": hours_b64,
        "bonus_points_ct_b64": bonus_b64,
    }, timeout=30)
    r.raise_for_status()
    print(r.json())


def cmd_employee_list(args):
    _need_requests()
    session_id = getattr(args, "session_id", None)
    if not session_id:
        print("--session-id required", file=sys.stderr)
        sys.exit(1)
    base = getattr(args, "server", DEFAULT_SERVER).rstrip("/")
    r = requests.get(f"{base}/v1/session/{session_id}/employees", timeout=30)
    r.raise_for_status()
    j = r.json()
    print("employee_ids:", j.get("employee_ids", []))
    print("count:", j.get("count", 0))


def _decrypt_one_ct_b64(ctx, sk, ct_b64: str) -> int:
    """Decrypt a single-value ciphertext (base64); return the int (slot 0)."""
    dec = _SEAL.Decryptor(ctx, sk)
    batch = _SEAL.BatchEncoder(ctx)
    ct = _SEAL.Ciphertext()
    raw = base64.b64decode(ct_b64)
    with tempfile.NamedTemporaryFile(suffix=".ct", delete=True) as t:
        Path(t.name).write_bytes(raw)
        ct.load(ctx, t.name)
    pt = dec.decrypt(ct)
    vals = batch.decode_int64(pt)
    return int(vals[0]) if vals else 0


def cmd_employee_get(args):
    _need_requests()
    session_id = getattr(args, "session_id", None)
    employee_id = getattr(args, "employee_id", None)
    if not session_id or not employee_id:
        print("--session-id and --employee-id required", file=sys.stderr)
        sys.exit(1)
    base = getattr(args, "server", DEFAULT_SERVER).rstrip("/")
    r = requests.get(f"{base}/v1/session/{session_id}/employees/{employee_id}", timeout=30)
    r.raise_for_status()
    data = r.json()
    if getattr(args, "decrypt", None):
        _need_seal()
        ctx = _load_context(OUT_DIR)
        sk = _SEAL.SecretKey()
        sk.load(ctx, str(OUT_DIR / "secret_key.seal"))
        salary_cents = _decrypt_one_ct_b64(ctx, sk, data["salary_ct_b64"])
        hours = _decrypt_one_ct_b64(ctx, sk, data["hours_ct_b64"])
        bonus_points = _decrypt_one_ct_b64(ctx, sk, data["bonus_points_ct_b64"])
        print(f"employee_id: {data['employee_id']}")
        print(f"salary_cents: {salary_cents}")
        print(f"hours: {hours}")
        print(f"bonus_points: {bonus_points}")
    else:
        print(json.dumps(data, indent=2))


def cmd_employee_adjust(args):
    """Add deltas to an employee's salary, hours, bonus_points without anyone seeing actual values. Encrypts deltas and sends to server; server adds homomorphically."""
    _need_requests()
    _need_seal()
    session_id = getattr(args, "session_id", None)
    employee_id = getattr(args, "employee_id", None)
    if not session_id or not employee_id:
        print("--session-id and --employee-id required", file=sys.stderr)
        sys.exit(1)
    salary_d = getattr(args, "salary_delta", None)
    hours_d = getattr(args, "hours_delta", None)
    bonus_d = getattr(args, "bonus_delta", None)
    if salary_d is None and hours_d is None and bonus_d is None:
        print("Provide at least one of --salary-delta, --hours-delta, --bonus-delta", file=sys.stderr)
        sys.exit(1)
    ctx = _load_context(OUT_DIR)
    pk = _SEAL.PublicKey()
    pk.load(ctx, str(OUT_DIR / "public_key.seal"))
    body = {}
    if salary_d is not None:
        body["salary_delta_ct_b64"] = base64.b64encode(_encrypt_one(ctx, pk, int(salary_d))).decode("ascii")
    if hours_d is not None:
        body["hours_delta_ct_b64"] = base64.b64encode(_encrypt_one(ctx, pk, int(hours_d))).decode("ascii")
    if bonus_d is not None:
        body["bonus_points_delta_ct_b64"] = base64.b64encode(_encrypt_one(ctx, pk, int(bonus_d))).decode("ascii")
    base = getattr(args, "server", DEFAULT_SERVER).rstrip("/")
    r = requests.patch(f"{base}/v1/session/{session_id}/employees/{employee_id}/adjust", json=body, timeout=30)
    _raise_for_status(r)
    print(r.json())


def cmd_employee_delete(args):
    _need_requests()
    session_id = getattr(args, "session_id", None)
    employee_id = getattr(args, "employee_id", None)
    if not session_id or not employee_id:
        print("--session-id and --employee-id required", file=sys.stderr)
        sys.exit(1)
    base = getattr(args, "server", DEFAULT_SERVER).rstrip("/")
    r = requests.delete(f"{base}/v1/session/{session_id}/employees/{employee_id}", timeout=30)
    r.raise_for_status()
    print(r.json())


def main():
    ap = argparse.ArgumentParser(prog="homolock-py", description="HomoLock-HR Python client")
    ap.add_argument("--server", default=DEFAULT_SERVER, help="Server base URL")
    sub = ap.add_subparsers(dest="cmd", required=True)

    # Session / keys / batch
    p_init = sub.add_parser("init-context")
    p_init.add_argument("--poly", type=int, default=8192, choices=[4096, 8192])
    p_init.set_defaults(run=cmd_init_context)

    p_keygen = sub.add_parser("keygen")
    p_keygen.set_defaults(run=cmd_keygen)

    p_enc = sub.add_parser("encrypt-hr", help="Encrypt HR data from CSV or JSON")
    p_enc.add_argument("--csv", type=str, default=None, help="Path to employees.csv")
    p_enc.add_argument("--json", type=str, default=None, help="Path to employees.json (array of {employee_id, salary_cents, hours, bonus_points})")
    p_enc.set_defaults(run=cmd_encrypt_hr)

    p_export_keys = sub.add_parser("export-session-keys", help="Print Session Keys JSON for Postman (from out/)")
    p_export_keys.add_argument("--session-id", type=str, default=None)
    p_export_keys.set_defaults(run=cmd_export_session_keys)

    p_up_s = sub.add_parser("upload-session")
    p_up_s.add_argument("--session-id", type=str, default=None)
    p_up_s.set_defaults(run=cmd_upload_session)

    p_up_d = sub.add_parser("upload-data")
    p_up_d.add_argument("--session-id", type=str, required=True)
    p_up_d.set_defaults(run=cmd_upload_data)

    p_comp = sub.add_parser("compute")
    p_comp.add_argument("--session-id", type=str, required=True)
    p_comp.add_argument("--bonus-bps", type=int, default=1000)
    p_comp.set_defaults(run=cmd_compute)

    p_fetch = sub.add_parser("fetch-decrypt")
    p_fetch.add_argument("--job-id", type=str, required=True)
    p_fetch.set_defaults(run=cmd_fetch_decrypt)

    p_run = sub.add_parser("run", help="Full flow: init → keygen → encrypt → upload → compute → fetch-decrypt")
    p_run.add_argument("--session-id", type=str, default=None, help="Session ID (default: run-<timestamp>)")
    p_run.add_argument("--csv", type=str, default=None, help="Path to employees.csv")
    p_run.add_argument("--poly", type=int, default=8192, choices=[4096, 8192])
    p_run.add_argument("--bonus-bps", type=int, default=1000)
    p_run.add_argument("--no-decrypt", action="store_true", help="Stop after compute; print job_ids only")
    p_run.set_defaults(run=cmd_run)

    # CRUD employees
    p_emp = sub.add_parser("employee")
    emp_sub = p_emp.add_subparsers(dest="employee_cmd", required=True)
    p_ec = emp_sub.add_parser("create")
    p_ec.add_argument("--session-id", required=True)
    p_ec.add_argument("--employee-id", required=True)
    p_ec.add_argument("--from-csv", action="store_true", help="Encrypt from data/employees.csv row")
    p_ec.add_argument("--csv", type=str, default=None)
    p_ec.set_defaults(run=cmd_employee_create)
    p_el = emp_sub.add_parser("list")
    p_el.add_argument("--session-id", required=True)
    p_el.set_defaults(run=cmd_employee_list)
    p_eg = emp_sub.add_parser("get")
    p_eg.add_argument("--session-id", required=True)
    p_eg.add_argument("--employee-id", required=True)
    p_eg.add_argument("--decrypt", action="store_true", help="Decrypt and print actual salary_cents, hours, bonus_points (requires out/secret_key.seal)")
    p_eg.set_defaults(run=cmd_employee_get)
    p_eadj = emp_sub.add_parser("adjust", help="Add encrypted deltas to salary/hours/bonus_points without revealing actual values")
    p_eadj.add_argument("--session-id", required=True)
    p_eadj.add_argument("--employee-id", required=True)
    p_eadj.add_argument("--salary-delta", type=int, default=None, help="Delta to add to salary_cents (e.g. 50000)")
    p_eadj.add_argument("--hours-delta", type=int, default=None, help="Delta to add to hours")
    p_eadj.add_argument("--bonus-delta", type=int, default=None, help="Delta to add to bonus_points")
    p_eadj.set_defaults(run=cmd_employee_adjust)
    p_ed = emp_sub.add_parser("delete")
    p_ed.add_argument("--session-id", required=True)
    p_ed.add_argument("--employee-id", required=True)
    p_ed.set_defaults(run=cmd_employee_delete)

    args = ap.parse_args()
    # Pass server into args for upload/compute/fetch/employee
    if hasattr(args, "run"):
        args.run(args)


if __name__ == "__main__":
    main()
