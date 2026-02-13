#!/usr/bin/env python3
"""
Generate static keys and ciphertexts for HomoLock-HR.
Writes to server_py/static/ so you can use them for POST /v1/run without running the full CLI.
Run from server_py: python -m scripts.generate_static_data
Requires: PySEAL (pip install seal).
"""
from __future__ import annotations

import json
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

# Output under server_py/static/
SCRIPT_DIR = Path(__file__).resolve().parent
STATIC_DIR = SCRIPT_DIR.parent / "static"

# Fixed demo data: employee_id, salary_cents, hours, bonus_points (5 rows)
STATIC_ROWS = [
    (1001, 850_000, 160, 10),
    (1002, 720_000, 160, 8),
    (1003, 950_000, 160, 12),
    (1004, 680_000, 140, 6),
    (1005, 1_100_000, 160, 15),
]


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

    # 1) Params
    parms = seal.EncryptionParameters(seal.scheme_type.bfv)
    parms.set_poly_modulus_degree(poly)
    parms.set_coeff_modulus(seal.CoeffModulus.BFVDefault(poly))
    parms.set_plain_modulus(seal.PlainModulus.Batching(poly, 20))
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

    # 3) Encrypt fixed data
    enc = seal.Encryptor(ctx, pk)
    batch = seal.BatchEncoder(ctx)

    def encrypt_one(value: int) -> bytes:
        pt = batch.encode(np.array([value], dtype=np.int64))
        ct = enc.encrypt(pt)
        with tempfile.NamedTemporaryFile(suffix=".ct", delete=True) as t:
            ct.save(t.name)
            return Path(t.name).read_bytes()

    salaries = [r[1] for r in STATIC_ROWS]
    hours = [r[2] for r in STATIC_ROWS]
    bonus_pts = [r[3] for r in STATIC_ROWS]
    salary_cts = [encrypt_one(v) for v in salaries]
    hours_cts = [encrypt_one(v) for v in hours]
    bonus_cts = [encrypt_one(v) for v in bonus_pts]

    save_ct_vec(STATIC_DIR / "salary.ct", salary_cts)
    save_ct_vec(STATIC_DIR / "hours.ct", hours_cts)
    save_ct_vec(STATIC_DIR / "bonus_points.ct", bonus_cts)
    (STATIC_DIR / "meta.json").write_text(json.dumps({"count": len(STATIC_ROWS), "version": 1}))
    print("Written salary.ct, hours.ct, bonus_points.ct, meta.json")

    print(f"\nStatic data is in: {STATIC_DIR}")
    print("Use these files for POST /v1/run (base64-encode each file).")
    print("Use secret_key.seal locally to decrypt results. Do not upload secret_key.seal.")


if __name__ == "__main__":
    main()
