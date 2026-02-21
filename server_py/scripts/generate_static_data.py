#!/usr/bin/env python3
"""
Generate static keys and ciphertexts for HomoLock-HR.
Writes to server_py/static/ so you can use them for POST /v1/run without running the full CLI.
Run from server_py: python -m scripts.generate_static_data
Requires: PySEAL (pip install seal).
"""
from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
from pathlib import Path

try:
    import numpy as np
    import seal
except ImportError as e:
    print("Need numpy and seal. Install with: pip install numpy seal", file=sys.stderr)
    sys.exit(1)


def _seal_scheme_bfv():
    """Return seal BFV scheme type (handles scheme_type.bfv or SchemeType.BFV)."""
    st = getattr(seal, "scheme_type", None) or getattr(seal, "SchemeType", None)
    if st is None:
        raise RuntimeError("seal has no scheme_type or SchemeType")
    return getattr(st, "bfv", None) or getattr(st, "BFV", None)


def _seal_coeff_modulus_bfv_default(poly: int):
    """Return BFV default coeff modulus (handles CoeffModulus.BFVDefault or bfv_default)."""
    cm = getattr(seal, "CoeffModulus", None)
    if cm is None:
        raise RuntimeError("seal has no CoeffModulus")
    fn = getattr(cm, "BFVDefault", None) or getattr(cm, "bfv_default", None)
    if fn is None:
        raise RuntimeError("seal CoeffModulus has no BFVDefault/bfv_default")
    return fn(poly)


def _seal_plain_modulus_batching(poly: int, bit_size: int):
    """Return plain modulus for batching (handles PlainModulus.Batching or Batching)."""
    pm = getattr(seal, "PlainModulus", None)
    if pm is None:
        raise RuntimeError("seal has no PlainModulus")
    fn = getattr(pm, "Batching", None) or getattr(pm, "batching", None)
    if fn is None:
        raise RuntimeError("seal PlainModulus has no Batching/batching")
    return fn(poly, bit_size)

# Output under server_py/static/
SCRIPT_DIR = Path(__file__).resolve().parent
SERVER_PY_DATA = SCRIPT_DIR.parent / "data"
STATIC_DIR = SCRIPT_DIR.parent / "static"
# When running in cloud, use HOMOLOCK_DATA_DIR so one dir holds employee data + static payload source
DATA_DIR = Path(os.environ.get("HOMOLOCK_DATA_DIR", "")).resolve() if os.environ.get("HOMOLOCK_DATA_DIR") else None

# Fallback demo data: (employee_id, salary_cents, hours, bonus_points) when data/employees.json is missing
STATIC_ROWS = [
    (1001, 850_000, 160, 10),
    (1002, 720_000, 160, 8),
    (1003, 950_000, 160, 12),
    (1004, 680_000, 140, 6),
    (1005, 1_100_000, 160, 15),
]


def load_employee_rows() -> list[tuple[int, int, int, int]]:
    """Load (employee_id, salary_cents, hours, bonus_points) from HOMOLOCK_DATA_DIR or server_py/data (employees.json then .csv), else STATIC_ROWS."""
    # When set (e.g. in cloud), try HOMOLOCK_DATA_DIR first
    bases = ([DATA_DIR] if DATA_DIR and DATA_DIR.is_dir() else []) + [SERVER_PY_DATA]
    for base in bases:
        json_path = base / "employees.json"
        if json_path.exists():
            rows = json.loads(json_path.read_text())
            if isinstance(rows, list):
                out = []
                for r in rows:
                    eid = r.get("employee_id", "")
                    try:
                        eid = int(eid) if isinstance(eid, (int, float)) else int(str(eid).strip() or "0")
                    except (ValueError, TypeError):
                        eid = len(out) + 1
                    out.append((eid, int(r.get("salary_cents", 0)), int(r.get("hours", 0)), int(r.get("bonus_points", 0))))
                if out:
                    return out
        csv_path = base / "employees.csv"
        if csv_path.exists():
            import csv as csv_module
            out = []
            with open(csv_path, newline="", encoding="utf-8") as f:
                for i, row in enumerate(csv_module.DictReader(f)):
                    eid = row.get("employee_id", "").strip() or str(i + 1)
                    try:
                        eid = int(eid)
                    except ValueError:
                        eid = i + 1
                    out.append((eid, int(row.get("salary_cents", 0)), int(row.get("hours", 0)), int(row.get("bonus_points", 0))))
            if out:
                return out
    return STATIC_ROWS


def save_ct_vec(path: Path, ct_bytes_list: list[bytes]) -> None:
    """Format [count: u32][len: u32][ct bytes]... (same as client)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(struct.pack("<I", len(ct_bytes_list)))
        for b in ct_bytes_list:
            f.write(struct.pack("<I", len(b)))
            f.write(b)


def main() -> None:
    poly = 8192
    STATIC_DIR.mkdir(parents=True, exist_ok=True)

    # 1) Params (compatible with scheme_type.bfv or SchemeType.BFV etc.)
    parms = seal.EncryptionParameters(_seal_scheme_bfv())
    parms.set_poly_modulus_degree(poly)
    parms.set_coeff_modulus(_seal_coeff_modulus_bfv_default(poly))
    parms.set_plain_modulus(_seal_plain_modulus_batching(poly, 20))
    parms.save(str(STATIC_DIR / "params.seal"))
    print("Written params.seal")

    # 2) Context and keys
    ctx = seal.SEALContext(parms)
    keygen = seal.KeyGenerator(ctx)
    sk = keygen.secret_key()
    pk = keygen.create_public_key()
    rk = keygen.create_relin_keys()
    sk.save(str(STATIC_DIR / "secret_key.seal"))
    pk.save(str(STATIC_DIR / "public_key.seal"))
    rk.save(str(STATIC_DIR / "relin_keys.seal"))
    try:
        gk = keygen.create_galois_keys()
        gk.save(str(STATIC_DIR / "galois_keys.seal"))
        print("Written galois_keys.seal")
    except Exception:
        pass
    print("Written secret_key.seal, public_key.seal, relin_keys.seal")

    # 3) Encrypt employee data from server_py/data/employees.json (or .csv), else built-in demo rows
    rows = load_employee_rows()
    src = "employees.json or .csv"
    if DATA_DIR and DATA_DIR.is_dir():
        if (DATA_DIR / "employees.json").exists():
            src = str(DATA_DIR / "employees.json")
        elif (DATA_DIR / "employees.csv").exists():
            src = str(DATA_DIR / "employees.csv")
    elif (SERVER_PY_DATA / "employees.json").exists():
        src = "server_py/data/employees.json"
    elif (SERVER_PY_DATA / "employees.csv").exists():
        src = "server_py/data/employees.csv"
    else:
        src = "built-in demo"
    print(f"Using {len(rows)} rows from {src}")
    total_salary = sum(r[1] for r in rows)
    total_hours_sum = sum(r[2] for r in rows)
    print(f"  sum(salary_cents)={total_salary}, sum(hours)={total_hours_sum}  (verify against {src})")

    enc = seal.Encryptor(ctx, pk)
    batch = seal.BatchEncoder(ctx)

    def encrypt_one(value: int) -> bytes:
        pt = batch.encode(np.array([value], dtype=np.int64))
        ct = enc.encrypt(pt)
        with tempfile.NamedTemporaryFile(suffix=".ct", delete=True) as t:
            ct.save(t.name)
            return Path(t.name).read_bytes()

    salaries = [r[1] for r in rows]
    hours = [r[2] for r in rows]
    bonus_pts = [r[3] for r in rows]
    salary_cts = [encrypt_one(v) for v in salaries]
    hours_cts = [encrypt_one(v) for v in hours]
    bonus_cts = [encrypt_one(v) for v in bonus_pts]

    save_ct_vec(STATIC_DIR / "salary.ct", salary_cts)
    save_ct_vec(STATIC_DIR / "hours.ct", hours_cts)
    save_ct_vec(STATIC_DIR / "bonus_points.ct", bonus_cts)
    (STATIC_DIR / "meta.json").write_text(json.dumps({"count": len(rows), "version": 1}))
    print("Written salary.ct, hours.ct, bonus_points.ct, meta.json")

    print(f"\nStatic data is in: {STATIC_DIR}")
    print("Use these files for POST /v1/run (base64-encode each file).")
    print("Use secret_key.seal locally to decrypt results. Do not upload secret_key.seal.")


if __name__ == "__main__":
    main()
