"""
Python HE engine using PySEAL (seal package).
Performs BFV homomorphic sum on ciphertexts in-process. Python only.
Falls back to None if seal is not installed; server then returns 503 for compute.
"""
from __future__ import annotations

import base64
import logging
import struct
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_SEAL_AVAILABLE = False
try:
    import seal
    _SEAL_AVAILABLE = True
except ImportError:
    seal = None  # type: ignore


def _seal_scheme_bfv():
    """Return seal BFV scheme type (handles scheme_type.bfv or SchemeType.BFV)."""
    if seal is None:
        raise RuntimeError("seal not available")
    st = getattr(seal, "scheme_type", None) or getattr(seal, "SchemeType", None)
    if st is None:
        raise RuntimeError("seal has no scheme_type or SchemeType")
    return getattr(st, "bfv", None) or getattr(st, "BFV", None)


def is_available() -> bool:
    return _SEAL_AVAILABLE


def _load_ct_vector(path: Path, context: "seal.SEALContext", work_dir: Path) -> list:
    """Load ciphertexts from file format: [count: u32][len: u32][ct bytes]... SEAL-Python loads from file path."""
    data = path.read_bytes()
    if len(data) < 4:
        raise ValueError("ct file too short")
    (count,) = struct.unpack("<I", data[:4])
    cts = []
    offset = 4
    for i in range(count):
        if offset + 4 > len(data):
            raise ValueError("ct file truncated")
        (ln,) = struct.unpack("<I", data[offset : offset + 4])
        offset += 4
        if offset + ln > len(data):
            raise ValueError("ct file truncated")
        chunk = bytes(data[offset : offset + ln])
        offset += ln
        tmp = work_dir / f"_ct_{i}.tmp"
        tmp.write_bytes(chunk)
        try:
            ct = seal.Ciphertext()
            ct.load(context, str(tmp))
            cts.append(ct)
        finally:
            tmp.unlink(missing_ok=True)
    return cts


def _save_ct(path: Path, ct: "seal.Ciphertext") -> None:
    """Save a single ciphertext to file (SEAL-Python save(path))."""
    ct.save(str(path))


def run_sum(job_dir: Path, op: str) -> Optional[Path]:
    """
    Run homomorphic sum in Python using seal.
    job_dir must contain: params.seal, relin_keys.seal, public_key.seal, and salary.ct or hours.ct.
    Writes result.ct and returns its path; returns None if seal is not available.
    """
    if not _SEAL_AVAILABLE or seal is None:
        return None
    job_dir = Path(job_dir)
    result_ct = job_dir / "result.ct"
    if op in ("total_payroll", "avg_salary", "bonus_pool"):
        in_path = job_dir / "salary.ct"
    elif op == "total_hours":
        in_path = job_dir / "hours.ct"
    else:
        raise ValueError(f"Unknown op: {op}")
    if not in_path.exists():
        raise FileNotFoundError(str(in_path))

    # PySEAL: EncryptionParameters(scheme_type) then load(); some builds use different scheme_type location
    params_path = str(job_dir / "params.seal")
    scheme = getattr(getattr(seal, "scheme_type", None), "bfv", None) or _seal_scheme_bfv()
    if scheme is None:
        raise RuntimeError("seal: could not get scheme_type.bfv")
    params = seal.EncryptionParameters(scheme)
    params.load(params_path)
    context = seal.SEALContext(params)
    # Optional: validate parameters (not all seal builds expose parameter_error_message)
    err_fn = getattr(context, "parameter_error_message", None)
    if callable(err_fn):
        err = err_fn()
        if err and str(err).strip() and str(err) != "valid":
            raise RuntimeError(f"Invalid parameters: {err}")

    cts = _load_ct_vector(in_path, context, job_dir)
    if not cts:
        raise ValueError("No ciphertexts in input")
    evaluator = seal.Evaluator(context)
    if len(cts) == 1:
        result = cts[0]
    else:
        # add_many( list[Ciphertext] ) -> Ciphertext (returns result, no in-place)
        result = evaluator.add_many(cts)
    _save_ct(result_ct, result)
    logger.info("Python HE engine wrote %s", result_ct)
    return result_ct


def add_two_ciphertexts(blob_dir: Path, ct1_bytes: bytes, ct2_bytes: bytes) -> bytes:
    """Homomorphically add two ciphertexts (same params from blob_dir). Returns result ciphertext as bytes."""
    if not _SEAL_AVAILABLE or seal is None:
        raise RuntimeError("seal not available")
    blob_dir = Path(blob_dir)
    params_path = str(blob_dir / "params.seal")
    if not (blob_dir / "params.seal").exists():
        raise FileNotFoundError("params.seal missing")
    scheme = getattr(getattr(seal, "scheme_type", None), "bfv", None) or _seal_scheme_bfv()
    params = seal.EncryptionParameters(scheme)
    params.load(params_path)
    context = seal.SEALContext(params)
    ct1 = seal.Ciphertext()
    ct2 = seal.Ciphertext()
    with tempfile.NamedTemporaryFile(suffix=".ct", delete=True) as t1:
        t1.write(ct1_bytes)
        t1.flush()
        ct1.load(context, t1.name)
    with tempfile.NamedTemporaryFile(suffix=".ct", delete=True) as t2:
        t2.write(ct2_bytes)
        t2.flush()
        ct2.load(context, t2.name)
    evaluator = seal.Evaluator(context)
    result = evaluator.add(ct1, ct2)
    with tempfile.NamedTemporaryFile(suffix=".ct", delete=True) as out:
        result.save(out.name)
        return Path(out.name).read_bytes()


def encrypt_one_plaintext(blob_dir: Path, value: int) -> bytes:
    """Encrypt a single int with the session's public key; return ciphertext bytes. Uses BatchEncoder.encode([value])."""
    if not _SEAL_AVAILABLE or seal is None:
        raise RuntimeError("seal not available")
    try:
        import numpy as np
    except ImportError:
        raise RuntimeError("numpy required for encryption")
    blob_dir = Path(blob_dir)
    params_path = str(blob_dir / "params.seal")
    pk_path = str(blob_dir / "public_key.seal")
    if not (blob_dir / "params.seal").exists() or not (blob_dir / "public_key.seal").exists():
        raise FileNotFoundError("params.seal or public_key.seal missing in session")
    scheme = getattr(getattr(seal, "scheme_type", None), "bfv", None) or _seal_scheme_bfv()
    params = seal.EncryptionParameters(scheme)
    params.load(params_path)
    context = seal.SEALContext(params)
    public_key = seal.PublicKey()
    public_key.load(context, pk_path)
    batch = seal.BatchEncoder(context)
    enc = seal.Encryptor(context, public_key)
    pt = batch.encode(np.array([value], dtype=np.int64))
    ct = enc.encrypt(pt)
    with tempfile.NamedTemporaryFile(suffix=".ct", delete=True) as t:
        ct.save(t.name)
        return Path(t.name).read_bytes()


def encrypt_employee_body(blob_dir: Path, employee_id: str, salary_cents: int, hours: int, bonus_points: int) -> dict:
    """Return JSON-serializable body for POST .../employees: employee_id and three *_ct_b64 fields."""
    s = encrypt_one_plaintext(blob_dir, salary_cents)
    h = encrypt_one_plaintext(blob_dir, hours)
    b = encrypt_one_plaintext(blob_dir, bonus_points)
    return {
        "employee_id": employee_id,
        "salary_ct_b64": base64.b64encode(s).decode("ascii"),
        "hours_ct_b64": base64.b64encode(h).decode("ascii"),
        "bonus_points_ct_b64": base64.b64encode(b).decode("ascii"),
    }
