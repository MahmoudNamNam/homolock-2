"""
Python HE engine using PySEAL (seal package).
Performs BFV homomorphic sum on ciphertexts in-process; no C++ worker required.
Falls back to None if seal is not installed (server will use C++ worker).
"""
from __future__ import annotations

import logging
import struct
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_SEAL_AVAILABLE = False
try:
    import seal
    _SEAL_AVAILABLE = True
except ImportError:
    seal = None  # type: ignore


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

    params = seal.EncryptionParameters()
    params.load(str(job_dir / "params.seal"))
    context = seal.SEALContext(params)
    err = context.parameter_error_message()
    if err and err != "valid":
        raise RuntimeError(f"Invalid parameters: {err}")

    cts = _load_ct_vector(in_path, context, job_dir)
    if not cts:
        raise ValueError("No ciphertexts in input")
    evaluator = seal.Evaluator(context)
    if len(cts) == 1:
        result = cts[0]
    else:
        result = seal.Ciphertext()
        evaluator.add_many(cts, result)
    _save_ct(result_ct, result)
    logger.info("Python HE engine wrote %s", result_ct)
    return result_ct
