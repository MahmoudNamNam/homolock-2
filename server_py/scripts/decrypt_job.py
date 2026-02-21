#!/usr/bin/env python3
"""
Fetch one job result from the server and decrypt it.

Usage:
  python -m scripts.decrypt_job JOB_ID [--server URL] [--keys out|static] [--debug]

Examples:
  python -m scripts.decrypt_job 790d3271-6493-4199-b86b-b180240ff834
  python -m scripts.decrypt_job 790d3271-6493-4199-b86b-b180240ff834 --server http://localhost:8000 --keys static --debug

Run from server_py. Requires: seal, requests.
Keys: --keys out (default) = client out/; --keys static = server_py/static/ (from generate_static_data).
"""
from __future__ import annotations

import argparse
import base64
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    import requests
    import seal
except ImportError:
    print("Need requests and seal. pip install requests seal", file=sys.stderr)
    sys.exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent
SERVER_PY = SCRIPT_DIR.parent
STATIC_DIR = SERVER_PY / "static"
OUT_DIR_CANDIDATES = [
    SERVER_PY.parent / "out",
    SERVER_PY / "out",
    Path.cwd() / "out",
]

DEFAULT_PLAIN_MODULUS = 2**20  # fallback when params don't expose it


def _seal_scheme_bfv():
    st = getattr(seal, "scheme_type", None) or getattr(seal, "SchemeType", None)
    if st is None:
        raise RuntimeError("seal has no scheme_type or SchemeType")
    return getattr(st, "bfv", None) or getattr(st, "BFV", None)


def resolve_keys_dir(keys_choice: str) -> Path | None:
    """Return path to directory containing params.seal and secret_key.seal, or None."""
    if keys_choice == "static":
        return STATIC_DIR if (STATIC_DIR / "params.seal").exists() and (STATIC_DIR / "secret_key.seal").exists() else None
    for d in OUT_DIR_CANDIDATES:
        if (d / "params.seal").exists() and (d / "secret_key.seal").exists():
            return d
    return None


def load_context_and_keys(keys_dir: Path) -> tuple[Any, Any, Any]:
    """Load SEAL context, secret key, and params from keys_dir. Returns (ctx, sk, params)."""
    params = seal.EncryptionParameters(_seal_scheme_bfv())
    params.load(str(keys_dir / "params.seal"))
    ctx = seal.SEALContext(params)
    sk = seal.SecretKey()
    sk.load(ctx, str(keys_dir / "secret_key.seal"))
    return ctx, sk, params


def get_plain_modulus(params: Any) -> int:
    """Extract plain modulus as int from SEAL params (PySEAL API varies)."""
    try:
        pm = getattr(params, "plain_modulus", None)
        if pm is None:
            return DEFAULT_PLAIN_MODULUS
        v = getattr(pm, "value", None)
        if callable(v):
            return int(v())
        if v is not None:
            return int(v)
    except Exception:
        pass
    return DEFAULT_PLAIN_MODULUS


def normalize_slot(value: int, plain_modulus: int) -> int:
    """Convert BFV decoded slot to unsigned (fix wraparound negative)."""
    return value if value >= 0 else value + plain_modulus


def decode_plaintext_slots(batch_encoder: Any, plaintext: Any) -> list[int]:
    """Decode plaintext to list of slot values (int). Handles decode_int64 vs decode."""
    if hasattr(batch_encoder, "decode_int64"):
        vals = batch_encoder.decode_int64(plaintext)
    else:
        vals = batch_encoder.decode(plaintext)
    if vals is None:
        return []
    try:
        return [int(x) for x in vals]
    except TypeError:
        return [int(vals)]


def decrypt_ciphertext_b64(ctx: Any, sk: Any, ct_b64: str) -> Any:
    """Load ciphertext from base64, decrypt; return Plaintext."""
    raw = base64.b64decode(ct_b64)
    ct = seal.Ciphertext()
    with tempfile.NamedTemporaryFile(suffix=".ct", delete=True) as f:
        f.write(raw)
        f.flush()
        ct.load(ctx, f.name)
    dec = seal.Decryptor(ctx, sk)
    return dec.decrypt(ct)


def decrypt_result(
    ctx: Any,
    sk: Any,
    params: Any,
    ct_b64: str,
    *,
    return_slots: bool = False,
) -> int | tuple[int, list[int], int]:
    """
    Decrypt result ciphertext and return first slot (sum) as int.
    If return_slots=True, return (value, slots, plain_modulus).
    """
    pt = decrypt_ciphertext_b64(ctx, sk, ct_b64)
    batch = seal.BatchEncoder(ctx)
    slots = decode_plaintext_slots(batch, pt)
    plain_mod = get_plain_modulus(params)
    first = int(slots[0]) if slots else 0
    value = normalize_slot(first, plain_mod)
    if return_slots:
        return value, slots, plain_mod
    return value


def fetch_job_result(server_base: str, job_id: str) -> dict:
    """GET /v1/result/{job_id}; raise on HTTP error or non-done status. Returns JSON."""
    r = requests.get(f"{server_base}/v1/result/{job_id}", timeout=30)
    r.raise_for_status()
    res = r.json()
    status = res.get("status")
    if status == "running":
        print("Job still running.", file=sys.stderr)
        sys.exit(1)
    if status == "error":
        print("Job failed:", res.get("error", "unknown"), file=sys.stderr)
        sys.exit(1)
    if status != "done":
        print(f"Unexpected status: {status}", file=sys.stderr)
        sys.exit(1)
    if not res.get("result_ciphertext_b64"):
        print("No result ciphertext in response.", file=sys.stderr)
        sys.exit(1)
    return res


def print_result(value: int, res: dict) -> None:
    """Print decrypted value (and derived avg/pool) according to result_type."""
    result_type = res.get("result_type", "")
    if result_type == "avg_salary" and res.get("count") is not None:
        count = res["count"]
        print(f"sum={value}, count={count}, avg={value // count}")
    elif result_type == "bonus_pool" and res.get("bonus_rate_bps") is not None:
        bps = res["bonus_rate_bps"]
        pool = value * bps // 10000
        print(f"sum={value}, bonus_rate_bps={bps}, bonus_pool={pool}")
    else:
        print(value)


def main() -> None:
    ap = argparse.ArgumentParser(description="Fetch one job result and decrypt it")
    ap.add_argument("job_id", help="Job ID from POST /v1/run or POST /v1/compute/*")
    ap.add_argument("--server", default="http://localhost:8000", help="Server base URL")
    ap.add_argument("--keys", choices=("out", "static"), default="out", help="Keys from out/ or static/")
    ap.add_argument("--debug", action="store_true", help="Print plain modulus and first decoded slots")
    args = ap.parse_args()

    server_base = args.server.rstrip("/")
    keys_dir = resolve_keys_dir(args.keys)
    if keys_dir is None:
        print("No keys found. Either:", file=sys.stderr)
        print("  1. Use static keys: cd server_py && python -m scripts.generate_static_data", file=sys.stderr)
        print("     Then: python -m scripts.decrypt_job JOB_ID --keys static", file=sys.stderr)
        print("  2. Or generate client keys (from repo root):", file=sys.stderr)
        print('     export PYTHONPATH="$(pwd)/server_py:$PYTHONPATH"', file=sys.stderr)
        print("     python3 -m client.cli init-context && python3 -m client.cli keygen", file=sys.stderr)
        print("     Then run decrypt_job again (with --keys out or default).", file=sys.stderr)
        sys.exit(1)

    res = fetch_job_result(server_base, args.job_id)
    ct_b64 = res["result_ciphertext_b64"]

    ctx, sk, params = load_context_and_keys(keys_dir)
    if args.debug:
        value, slots, plain_mod = decrypt_result(ctx, sk, params, ct_b64, return_slots=True)
        print(f"plain_modulus={plain_mod}", file=sys.stderr)
        n = min(24, len(slots))
        print(f"first {n} slot(s) (raw): {slots[:n]}", file=sys.stderr)
        norm = [normalize_slot(int(s), plain_mod) for s in slots[:n]]
        print(f"first {n} slot(s) (normalized): {norm}", file=sys.stderr)
    else:
        value = decrypt_result(ctx, sk, params, ct_b64)

    print_result(value, res)


if __name__ == "__main__":
    main()
