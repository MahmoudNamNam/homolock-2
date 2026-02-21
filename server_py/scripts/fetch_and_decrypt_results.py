#!/usr/bin/env python3
"""
Fetch job results from the server and decrypt with static secret key so you can see real data.
Usage:
  # From run response (paste JSON or pipe):
  curl -s -X POST http://localhost:8000/v1/run -H "Content-Type: application/json" -d '{}' | python -m scripts.fetch_and_decrypt_results --server http://localhost:8000

  # Or pass job IDs explicitly:
  python -m scripts.fetch_and_decrypt_results --server http://localhost:8000 <payroll_id> <avg_id> <hours_id> <bonus_id>

Run from server_py. Requires: seal, requests.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import tempfile
from pathlib import Path

try:
    import requests
    import seal
except ImportError as e:
    print("Need requests and seal. pip install requests seal", file=sys.stderr)
    sys.exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent
STATIC_DIR = SCRIPT_DIR.parent / "static"

# Plain modulus for Batching(poly, 20); normalizes BFV decoded wraparound (negative -> unsigned).
PLAIN_MODULUS_BATCHING_20 = 2**20


def _normalize_decoded_value(value: int, plain_modulus: int = PLAIN_MODULUS_BATCHING_20) -> int:
    """Convert BFV decoded value to unsigned interpretation (fix wraparound negative)."""
    return value if value >= 0 else value + plain_modulus


def _seal_scheme_bfv():
    st = getattr(seal, "scheme_type", None) or getattr(seal, "SchemeType", None)
    if st is None:
        raise RuntimeError("seal has no scheme_type or SchemeType")
    return getattr(st, "bfv", None) or getattr(st, "BFV", None)


def load_context_and_key():
    scheme = _seal_scheme_bfv()
    params = seal.EncryptionParameters(scheme)
    params.load(str(STATIC_DIR / "params.seal"))
    ctx = seal.SEALContext(params)
    sk = seal.SecretKey()
    sk.load(ctx, str(STATIC_DIR / "secret_key.seal"))
    return ctx, sk


def decrypt_result(ctx, sk, ct_b64: str) -> int:
    dec = seal.Decryptor(ctx, sk)
    batch = seal.BatchEncoder(ctx)
    ct = seal.Ciphertext()
    raw = base64.b64decode(ct_b64)
    with tempfile.NamedTemporaryFile(suffix=".ct", delete=True) as t:
        Path(t.name).write_bytes(raw)
        ct.load(ctx, t.name)
    pt = dec.decrypt(ct)
    # PySEAL API varies: decode_int64 or decode
    if hasattr(batch, "decode_int64"):
        vals = batch.decode_int64(pt)
    else:
        vals = batch.decode(pt)
    try:
        raw = int(vals[0]) if vals is not None and len(vals) else 0
    except (TypeError, IndexError):
        raw = int(vals) if vals is not None else 0
    return _normalize_decoded_value(raw)


def main():
    ap = argparse.ArgumentParser(description="Fetch and decrypt /v1/run results")
    ap.add_argument("--server", default="http://localhost:8000", help="Server base URL")
    ap.add_argument("job_ids", nargs="*", help="Optional: payroll_id avg_id hours_id bonus_id (or read JSON from stdin)")
    args = ap.parse_args()
    server = args.server.rstrip("/")

    if not (STATIC_DIR / "secret_key.seal").exists():
        print("Missing static/secret_key.seal. Run: python -m scripts.generate_static_data", file=sys.stderr)
        sys.exit(1)

    # Get job_ids: from args or from stdin (run response JSON)
    if args.job_ids and len(args.job_ids) >= 4:
        job_ids = {
            "total_payroll": args.job_ids[0],
            "avg_salary": args.job_ids[1],
            "total_hours": args.job_ids[2],
            "bonus_pool": args.job_ids[3],
        }
    else:
        try:
            data = json.load(sys.stdin)
        except json.JSONDecodeError:
            print("Paste the JSON from POST /v1/run (session_id + job_ids), or pass 4 job_ids as arguments.", file=sys.stderr)
            sys.exit(1)
        job_ids = data.get("job_ids") or data
        if not job_ids or "total_payroll" not in job_ids:
            print("JSON must contain job_ids with total_payroll, avg_salary, total_hours, bonus_pool.", file=sys.stderr)
            sys.exit(1)

    ctx, sk = load_context_and_key()

    for label, result_type in [
        ("Total payroll (cents)", "total_payroll"),
        ("Avg salary (sum, count, avg)", "avg_salary"),
        ("Total hours", "total_hours"),
        ("Bonus pool (sum × rate)", "bonus_pool"),
    ]:
        jid = job_ids.get(result_type)
        if not jid:
            continue
        r = requests.get(f"{server}/v1/result/{jid}", timeout=30)
        r.raise_for_status()
        res = r.json()
        if res.get("status") != "done":
            print(f"{label}: status={res.get('status')}")
            continue
        ct_b64 = res.get("result_ciphertext_b64")
        if not ct_b64:
            print(f"{label}: no ciphertext")
            continue
        value = decrypt_result(ctx, sk, ct_b64)
        if result_type == "avg_salary" and res.get("count"):
            count = res["count"]
            print(f"{label}: sum={value}, count={count}, avg={value // count}")
        elif result_type == "bonus_pool" and res.get("bonus_rate_bps") is not None:
            bps = res["bonus_rate_bps"]
            pool = value * bps // 10000
            print(f"{label}: sum={value}, bonus_rate_bps={bps}, bonus_pool={pool}")
        else:
            print(f"{label}: {value}")


if __name__ == "__main__":
    main()
