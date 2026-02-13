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
import uuid
from pathlib import Path

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


def _need_seal():
    if _SEAL is None:
        print("PySEAL (seal) is not installed. Use C++ client for encrypt/decrypt, or install SEAL-Python.", file=sys.stderr)
        sys.exit(1)


def _session_id() -> str:
    return str(uuid.uuid4())[:8]


# ---------- SEAL helpers ----------

def _load_context(out_dir: Path):
    _need_seal()
    params = _SEAL.EncryptionParameters()
    params.load(str(out_dir / "params.seal"))
    ctx = _SEAL.SEALContext(params)
    err = ctx.parameter_error_message()
    if err and err != "valid":
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
    pt = _SEAL.Plaintext()
    batch.encode([value], pt)
    ct = _SEAL.Ciphertext()
    enc.encrypt(pt, ct)
    with tempfile.NamedTemporaryFile(suffix=".ct", delete=True) as t:
        ct.save(t.name)
        return Path(t.name).read_bytes()


# ---------- Commands ----------

def cmd_init_context(args):
    """Create params.seal (poly 4096 or 8192)."""
    _need_seal()
    poly = getattr(args, "poly", 8192)
    parms = _SEAL.EncryptionParameters(_SEAL.scheme_type.BFV)
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


def cmd_encrypt_hr(args):
    """Read data/employees.csv; write out/salary.ct, hours.ct, bonus_points.ct, meta.json."""
    _need_seal()
    csv_path = getattr(args, "csv", None) or DATA_DIR / "employees.csv"
    if not Path(csv_path).exists():
        print(f"File not found: {csv_path}", file=sys.stderr)
        sys.exit(1)
    ctx = _load_context(OUT_DIR)
    pk = _SEAL.PublicKey()
    pk.load(ctx, str(OUT_DIR / "public_key.seal"))
    rows = []
    with open(csv_path, newline="") as f:
        for r in csv.DictReader(f):
            rows.append({
                "employee_id": r["employee_id"].strip(),
                "salary_cents": int(r["salary_cents"]),
                "hours": int(r["hours"]),
                "bonus_points": int(r["bonus_points"]),
            })
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
    print(f"Written out/salary.ct, out/hours.ct, out/bonus_points.ct, out/meta.json ({len(rows)} rows)")


def cmd_upload_session(args):
    _need_requests()
    base = getattr(args, "server", DEFAULT_SERVER).rstrip("/")
    session_id = getattr(args, "session_id", None) or _session_id()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    params_b64 = base64.b64encode((OUT_DIR / "params.seal").read_bytes()).decode("ascii")
    pk_b64 = base64.b64encode((OUT_DIR / "public_key.seal").read_bytes()).decode("ascii")
    relin_b64 = base64.b64encode((OUT_DIR / "relin_keys.seal").read_bytes()).decode("ascii")
    payload = {"session_id": session_id, "params_b64": params_b64, "public_key_b64": pk_b64, "relin_keys_b64": relin_b64}
    if (OUT_DIR / "galois_keys.seal").exists():
        payload["galois_keys_b64"] = base64.b64encode((OUT_DIR / "galois_keys.seal").read_bytes()).decode("ascii")
    r = requests.post(f"{base}/v1/session/keys", json=payload, timeout=30)
    r.raise_for_status()
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
    r.raise_for_status()
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
        r.raise_for_status()
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
    r.raise_for_status()
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
    pt = _SEAL.Plaintext()
    dec.decrypt(ct, pt)
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
    print(json.dumps(r.json(), indent=2))


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

    p_enc = sub.add_parser("encrypt-hr")
    p_enc.add_argument("--csv", type=str, default=None)
    p_enc.set_defaults(run=cmd_encrypt_hr)

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
    p_eg.set_defaults(run=cmd_employee_get)
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
