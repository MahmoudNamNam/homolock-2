"""
HomoLock-HR FastAPI server.
File-based storage (JSON + blobs). HE via Python (PySEAL) only. CRUD on encrypted HR employee data.
Secret key is NEVER stored or logged.
"""

import base64
import binascii
import json
import logging
import os
import re
import shutil
import struct
import time
import uuid
from pathlib import Path

from typing import Optional

from fastapi import Body, FastAPI, HTTPException
from pydantic import BaseModel
from starlette.middleware.gzip import GZipMiddleware

from app.storage.file_db import FileDB
from app.he_engine import (
    add_two_ciphertexts as _he_add_two_ciphertexts,
    encrypt_employee_body as _he_encrypt_employee_body,
    encrypt_one_plaintext as _he_encrypt_one_plaintext,
    is_available as _he_available,
    run_sum as _he_run_sum,
)

# Lazy alias so we can use he_engine.is_available / he_engine.run_sum
class _HeEngine:
    is_available = staticmethod(_he_available)
    run_sum = staticmethod(_he_run_sum)


he_engine = _HeEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="HomoLock-HR",
    version="0.1.0",
    description="Privacy-preserving HR/payroll: client encrypts, server computes on ciphertext. All paths relative to HOMOLOCK_DATA_DIR (default data/).",
    openapi_tags=[
        {"name": "health", "description": "Liveness check"},
        {"name": "run", "description": "One-shot: upload keys + data, run all four computations. Body optional (use static data)."},
        {"name": "session", "description": "Session keys and batch ciphertext upload"},
        {"name": "compute", "description": "Trigger HE computations (total_payroll, avg_salary, total_hours, bonus_pool)"},
        {"name": "results", "description": "Get job result ciphertext (decrypt locally)"},
        {"name": "employees", "description": "CRUD per-employee encrypted data"},
    ],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)  # Compress large responses (e.g. session-keys, session-data)

# File-based storage: base dir from env (default "data" relative to cwd)
DATA_DIR = Path(os.environ.get("HOMOLOCK_DATA_DIR", "data"))
db = FileDB(DATA_DIR)

# Static keys/ciphertexts for zero-config run (server_py/static/)
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

# Session ID: non-empty, alphanumeric + hyphen + underscore (no path traversal)
SESSION_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def _validate_session_id(session_id: str) -> None:
    if not session_id or not SESSION_ID_RE.match(session_id):
        raise HTTPException(status_code=400, detail="Invalid session_id (use alphanumeric, hyphen, underscore only)")


# ---------------------------------------------------------------------------
# Schemas (Pydantic v2)
# ---------------------------------------------------------------------------

class SessionKeysRequest(BaseModel):
    session_id: str
    params_b64: str
    public_key_b64: str
    relin_keys_b64: str
    galois_keys_b64: str | None = None


class SessionDataRequest(BaseModel):
    session_id: str
    salary_ct_b64: str
    hours_ct_b64: str
    bonus_points_ct_b64: str
    count: int


class ComputeSessionRequest(BaseModel):
    session_id: str


class BonusPoolRequest(BaseModel):
    session_id: str
    bonus_rate_bps: int = 1000


class EmployeeDataRequest(BaseModel):
    """Single employee encrypted payload (create/update)."""
    employee_id: str
    salary_ct_b64: str
    hours_ct_b64: str
    bonus_points_ct_b64: str


class EmployeePlainRequest(BaseModel):
    """Single employee plain values. Server encrypts and stores (no base64 from client)."""
    employee_id: str
    salary_cents: int
    hours: int
    bonus_points: int


class FromBatchRequest(BaseModel):
    """Optional: employee_ids for from-batch. Order must match batch (first row = first id). If omitted, uses \"1\", \"2\", ... \"N\"."""
    employee_ids: list[str] | None = None


class AdjustEmployeeRequest(BaseModel):
    """Deltas to add (plain ints or encrypted). Send plain salary_delta/hours_delta/bonus_points_delta and server encrypts; or send *_ct_b64. Omit to leave unchanged."""
    salary_delta: int | None = None
    hours_delta: int | None = None
    bonus_points_delta: int | None = None
    salary_delta_ct_b64: str | None = None
    hours_delta_ct_b64: str | None = None
    bonus_points_delta_ct_b64: str | None = None


class RunRequest(BaseModel):
    """One-shot: upload keys + data and run all four computations. All fields optional: omit body or use {} to use static data from server_py/static/."""
    session_id: str | None = None
    params_b64: str | None = None
    public_key_b64: str | None = None
    relin_keys_b64: str | None = None
    galois_keys_b64: str | None = None
    salary_ct_b64: str | None = None
    hours_ct_b64: str | None = None
    bonus_points_ct_b64: str | None = None
    count: int | None = None
    bonus_rate_bps: int = 1000


# Response models (for OpenAPI / Swagger)
class HealthResponse(BaseModel):
    status: str


class RunResponse(BaseModel):
    session_id: str
    job_ids: dict[str, str]


class SessionOkResponse(BaseModel):
    ok: bool


class CreateEmployeeResponse(BaseModel):
    ok: bool
    employee_id: str


class ListEmployeesResponse(BaseModel):
    employee_ids: list[str]
    count: int


class GetEmployeeResponse(BaseModel):
    employee_id: str
    salary_ct_b64: str
    hours_ct_b64: str
    bonus_points_ct_b64: str


class DeleteEmployeeResponse(BaseModel):
    ok: bool
    employee_id: str


class ComputeJobResponse(BaseModel):
    job_id: str
    count: int | None = None
    bonus_rate_bps: int | None = None


class ResultResponse(BaseModel):
    job_id: str
    status: str
    result_ciphertext_b64: str
    result_type: str
    count: int | None = None
    bonus_rate_bps: int | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EMPLOYEE_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def _validate_employee_id(employee_id: str) -> None:
    if not employee_id or not EMPLOYEE_ID_RE.match(employee_id):
        raise HTTPException(status_code=400, detail="Invalid employee_id (alphanumeric, hyphen, underscore only)")

def get_session(session_id: str) -> dict:
    """Return session doc from FileDB; 404 if not found."""
    _validate_session_id(session_id)
    s = db.get_session(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    return s


def _blob_dir(s: dict) -> Path:
    """Resolve blob_dir from session doc (relative to DATA_DIR or absolute)."""
    p = Path(s["blob_dir"])
    return (DATA_DIR / p) if not p.is_absolute() else p


def _blob_dir_str(blob_dir: Path) -> str:
    """Store blob_dir in session doc: relative to DATA_DIR so resolution works from any cwd."""
    try:
        return str(blob_dir.relative_to(DATA_DIR))
    except ValueError:
        return str(blob_dir)


def _run_compute(op: str, work_dir: Path) -> Path:
    """Run HE sum via Python (PySEAL). Returns path to result.ct."""
    if not he_engine.is_available():
        raise HTTPException(
            status_code=503,
            detail="HE engine unavailable. Install PySEAL: pip install seal (or build from source: server_py/install_seal_python.sh). See server_py/docs/TROUBLESHOOTING.md",
        )
    result_ct = work_dir / "result.ct"
    try:
        out = he_engine.run_sum(work_dir, op)
        if out is not None and out.exists():
            return out
    except Exception as e:
        logger.exception("Python HE engine failed: %s", e)
        raise HTTPException(status_code=500, detail=f"HE computation failed: {e}")
    raise HTTPException(status_code=500, detail="HE engine did not produce result.ct")


def _merge_employee_ct_files(blob_dir: Path, field: str, out_path: Path) -> int:
    """Merge per-employee ct files (employees/{id}/{field}.ct) into one file; return count."""
    employees_dir = blob_dir / "employees"
    if not employees_dir.exists():
        return 0
    parts: list[bytes] = []
    count = 0
    for emp_dir in sorted(employees_dir.iterdir()):
        if not emp_dir.is_dir():
            continue
        f = emp_dir / f"{field}.ct"
        if not f.exists():
            continue
        data = f.read_bytes()
        if len(data) < 8:
            continue
        (n,) = struct.unpack("<I", data[:4])
        offset = 4
        for _ in range(n):
            if offset + 4 > len(data):
                break
            (ln,) = struct.unpack("<I", data[offset : offset + 4])
            offset += 4
            if offset + ln > len(data):
                break
            parts.append(data[offset : offset + ln])
            count += 1
            offset += ln
    if not parts:
        return 0
    with open(out_path, "wb") as out:
        out.write(struct.pack("<I", count))
        for p in parts:
            out.write(struct.pack("<I", len(p)))
            out.write(p)
    return count


def _prepare_compute_input(s: dict, blob_dir: Path, job_dir: Path, op: str) -> int:
    """Copy or merge inputs into job_dir; return employee count for this op."""
    employees = s.get("employees") or {}
    if employees:
        # Per-employee CRUD: merge employees' cts into salary.ct / hours.ct
        if op in ("total_payroll", "avg_salary", "bonus_pool"):
            n = _merge_employee_ct_files(blob_dir, "salary", job_dir / "salary.ct")
        else:
            n = _merge_employee_ct_files(blob_dir, "hours", job_dir / "hours.ct")
        if n == 0:
            raise HTTPException(status_code=400, detail="No employee data; add employees first")
    else:
        # Legacy batch: session-level files
        if op in ("total_payroll", "avg_salary", "bonus_pool"):
            src = blob_dir / "salary.ct"
            if not src.exists():
                raise HTTPException(status_code=400, detail="Session data missing; upload ciphertexts or add employees first")
            shutil.copy2(src, job_dir / "salary.ct")
        else:
            src = blob_dir / "hours.ct"
            if not src.exists():
                raise HTTPException(status_code=400, detail="Session data missing; upload ciphertexts or add employees first")
            shutil.copy2(src, job_dir / "hours.ct")
        n = s.get("count") or 0
    return n


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", tags=["health"], response_model=HealthResponse)
def health():
    """Liveness. Returns {"status":"ok"}."""
    return {"status": "ok"}


@app.post("/v1/session/keys", tags=["session"], response_model=SessionOkResponse)
def session_keys(req: SessionKeysRequest):
    """Create session with HE params and public keys. Required before session/data or compute.
    If the session already exists, existing data (ciphertexts, employees) is preserved."""
    _validate_session_id(req.session_id)
    try:
        blob_dir = db.session_blob_dir(req.session_id)
        # Write keys to blob dir (never log key/ciphertext contents)
        (blob_dir / "params.seal").write_bytes(base64.b64decode(req.params_b64))
        (blob_dir / "public_key.seal").write_bytes(base64.b64decode(req.public_key_b64))
        (blob_dir / "relin_keys.seal").write_bytes(base64.b64decode(req.relin_keys_b64))
        if req.galois_keys_b64:
            (blob_dir / "galois_keys.seal").write_bytes(base64.b64decode(req.galois_keys_b64))
        now = time.time()
        existing = db.get_session(req.session_id)
        session_doc = {
            "session_id": req.session_id,
            "blob_dir": _blob_dir_str(blob_dir),
            "params_path": str(blob_dir / "params.seal"),
            "public_key_path": str(blob_dir / "public_key.seal"),
            "relin_keys_path": str(blob_dir / "relin_keys.seal"),
            "salary_ct_path": existing.get("salary_ct_path") if existing else None,
            "hours_ct_path": existing.get("hours_ct_path") if existing else None,
            "bonus_points_ct_path": existing.get("bonus_points_ct_path") if existing else None,
            "count": existing.get("count", 0) if existing else 0,
            "employees": existing.get("employees", {}) if existing else {},
            "created_at": existing.get("created_at", now) if existing else now,
            "updated_at": now,
        }
        db.upsert_session(req.session_id, session_doc)
        logger.info("Session created: %s", req.session_id)
        return {"ok": True}
    except Exception as e:
        logger.exception("session_keys failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/static/session-keys", tags=["session"])
def get_static_session_keys(session_id: str = "my-session"):
    """Return session-keys JSON from server static data. Use as body for POST /v1/session/keys (endpoints only, no CLI)."""
    _validate_session_id(session_id)
    payload = _load_static_payload()
    return {
        "session_id": session_id,
        "params_b64": payload["params_b64"],
        "public_key_b64": payload["public_key_b64"],
        "relin_keys_b64": payload["relin_keys_b64"],
        "galois_keys_b64": payload.get("galois_keys_b64"),
    }


@app.get("/v1/static/session-data", tags=["session"])
def get_static_session_data(session_id: str = "my-session"):
    """Return session-data JSON from server static data. Use as body for POST /v1/session/data (endpoints only, no CLI)."""
    _validate_session_id(session_id)
    payload = _load_static_payload()
    return {
        "session_id": session_id,
        "salary_ct_b64": payload["salary_ct_b64"],
        "hours_ct_b64": payload["hours_ct_b64"],
        "bonus_points_ct_b64": payload["bonus_points_ct_b64"],
        "count": payload["count"],
    }


@app.post("/v1/session/data", tags=["session"], response_model=SessionOkResponse)
def session_data(req: SessionDataRequest):
    """Upload batch ciphertexts for a session. Call after session/keys."""
    s = get_session(req.session_id)
    blob_dir = _blob_dir(s)
    # Ensure session has keys (required before data)
    if not (blob_dir / "params.seal").exists():
        raise HTTPException(status_code=400, detail="Session keys missing; upload keys first")
    (blob_dir / "salary.ct").write_bytes(_b64decode_safe(req.salary_ct_b64, "salary_ct_b64"))
    (blob_dir / "hours.ct").write_bytes(_b64decode_safe(req.hours_ct_b64, "hours_ct_b64"))
    (blob_dir / "bonus_points.ct").write_bytes(_b64decode_safe(req.bonus_points_ct_b64, "bonus_points_ct_b64"))
    now = time.time()
    s["salary_ct_path"] = str(blob_dir / "salary.ct")
    s["hours_ct_path"] = str(blob_dir / "hours.ct")
    s["bonus_points_ct_path"] = str(blob_dir / "bonus_points.ct")
    s["count"] = req.count
    s.setdefault("employees", {})
    s["updated_at"] = now
    db.upsert_session(req.session_id, s)
    return {"ok": True}


def _b64decode_safe(data_b64: str, field: str) -> bytes:
    """Decode base64; raise HTTP 400 with clear message if invalid."""
    try:
        return base64.b64decode(data_b64)
    except (binascii.Error, ValueError) as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid base64 in {field}. Use base64-encoded file contents (e.g. from out/params.seal, out/public_key.seal). Example: run the CLI once to generate out/, then base64-encode those files.",
        ) from e


def _load_static_payload() -> dict:
    """Load keys and ciphertexts from STATIC_DIR; raise 503 if static data missing."""
    if not STATIC_DIR.is_dir():
        raise HTTPException(
            status_code=503,
            detail="No static data. Run: cd server_py && python -m scripts.generate_static_data",
        )
    required = ["params.seal", "public_key.seal", "relin_keys.seal", "salary.ct", "hours.ct", "bonus_points.ct", "meta.json"]
    for name in required:
        if not (STATIC_DIR / name).exists():
            raise HTTPException(status_code=503, detail=f"Static data incomplete: missing {name}. Run: python -m scripts.generate_static_data")
    meta = json.loads((STATIC_DIR / "meta.json").read_text())
    payload = {
        "params_b64": base64.b64encode((STATIC_DIR / "params.seal").read_bytes()).decode("ascii"),
        "public_key_b64": base64.b64encode((STATIC_DIR / "public_key.seal").read_bytes()).decode("ascii"),
        "relin_keys_b64": base64.b64encode((STATIC_DIR / "relin_keys.seal").read_bytes()).decode("ascii"),
        "salary_ct_b64": base64.b64encode((STATIC_DIR / "salary.ct").read_bytes()).decode("ascii"),
        "hours_ct_b64": base64.b64encode((STATIC_DIR / "hours.ct").read_bytes()).decode("ascii"),
        "bonus_points_ct_b64": base64.b64encode((STATIC_DIR / "bonus_points.ct").read_bytes()).decode("ascii"),
        "count": meta.get("count", 0),
    }
    if (STATIC_DIR / "galois_keys.seal").exists():
        payload["galois_keys_b64"] = base64.b64encode((STATIC_DIR / "galois_keys.seal").read_bytes()).decode("ascii")
    else:
        payload["galois_keys_b64"] = None
    return payload


@app.post("/v1/run", tags=["run"], response_model=RunResponse)
def run_all(req: Optional[RunRequest] = Body(None)):
    """
    One-shot: upload keys + data and run all four computations.
    **No config:** omit body or send `{}` to use static data from server_py/static/ (run `python -m scripts.generate_static_data` once).
    Returns session_id and job_ids. Get results with GET /v1/result/{job_id}.
    """
    if req is None:
        req = RunRequest()
    # Use static data when no payload provided
    if req.params_b64 is None:
        payload = _load_static_payload()
        params_b64 = payload["params_b64"]
        public_key_b64 = payload["public_key_b64"]
        relin_keys_b64 = payload["relin_keys_b64"]
        galois_keys_b64 = payload.get("galois_keys_b64")
        salary_ct_b64 = payload["salary_ct_b64"]
        hours_ct_b64 = payload["hours_ct_b64"]
        bonus_points_ct_b64 = payload["bonus_points_ct_b64"]
        count = payload["count"]
        # Reuse same session when no session_id so data (e.g. employees) is not lost on each run
        session_id = req.session_id or "run-static"
        bonus_rate_bps = req.bonus_rate_bps
    else:
        params_b64 = req.params_b64
        public_key_b64 = req.public_key_b64
        relin_keys_b64 = req.relin_keys_b64
        galois_keys_b64 = req.galois_keys_b64
        salary_ct_b64 = req.salary_ct_b64
        hours_ct_b64 = req.hours_ct_b64
        bonus_points_ct_b64 = req.bonus_points_ct_b64
        count = req.count if req.count is not None else 0
        # Same default as static: one session dir for all runs when session_id not provided
        session_id = req.session_id or "run-static"
        bonus_rate_bps = req.bonus_rate_bps

    _validate_session_id(session_id)
    try:
        blob_dir = db.session_blob_dir(session_id)
        (blob_dir / "params.seal").write_bytes(_b64decode_safe(params_b64, "params_b64"))
        (blob_dir / "public_key.seal").write_bytes(_b64decode_safe(public_key_b64, "public_key_b64"))
        (blob_dir / "relin_keys.seal").write_bytes(_b64decode_safe(relin_keys_b64, "relin_keys_b64"))
        if galois_keys_b64:
            (blob_dir / "galois_keys.seal").write_bytes(_b64decode_safe(galois_keys_b64, "galois_keys_b64"))
        now = time.time()
        existing = db.get_session(session_id)
        session_doc = {
            "session_id": session_id,
            "blob_dir": _blob_dir_str(blob_dir),
            "params_path": str(blob_dir / "params.seal"),
            "public_key_path": str(blob_dir / "public_key.seal"),
            "relin_keys_path": str(blob_dir / "relin_keys.seal"),
            "salary_ct_path": None,
            "hours_ct_path": None,
            "bonus_points_ct_path": None,
            "count": count,
            "employees": existing.get("employees", {}) if existing else {},
            "created_at": existing.get("created_at", now) if existing else now,
            "updated_at": now,
        }
        db.upsert_session(session_id, session_doc)
        (blob_dir / "salary.ct").write_bytes(_b64decode_safe(salary_ct_b64, "salary_ct_b64"))
        (blob_dir / "hours.ct").write_bytes(_b64decode_safe(hours_ct_b64, "hours_ct_b64"))
        (blob_dir / "bonus_points.ct").write_bytes(_b64decode_safe(bonus_points_ct_b64, "bonus_points_ct_b64"))
        session_doc["salary_ct_path"] = str(blob_dir / "salary.ct")
        session_doc["hours_ct_path"] = str(blob_dir / "hours.ct")
        session_doc["bonus_points_ct_path"] = str(blob_dir / "bonus_points.ct")
        session_doc["updated_at"] = time.time()
        db.upsert_session(session_id, session_doc)
        job_ids = {
            "total_payroll": _enqueue_compute(session_id, "total_payroll", "total_payroll"),
            "avg_salary": _enqueue_compute(session_id, "avg_salary", "avg_salary"),
            "total_hours": _enqueue_compute(session_id, "total_hours", "total_hours"),
            "bonus_pool": _enqueue_compute(session_id, "bonus_pool", "bonus_pool", bonus_rate_bps=bonus_rate_bps),
        }
        # Auto-create per-employee entries from data/employees.json or employees.csv so GET .../employees returns them
        _create_employees_from_batch_if_data(session_id)
        return {"session_id": session_id, "job_ids": job_ids}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("run_all failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


# ---------- CRUD: HR employees (encrypted per employee) ----------

def _load_employee_ids_from_data_dir(batch_count: int | None = None) -> list[str] | None:
    """Load ordered employee_ids from DATA_DIR/employees.json or employees.csv.
    If batch_count is set, prefer the file whose row count equals batch_count (so IDs match the batch).
    Return None if neither exists, empty, or no list length matches batch_count when batch_count is set."""
    import csv as csv_module
    json_ids: list[str] | None = None
    csv_ids: list[str] | None = None
    json_path = DATA_DIR / "employees.json"
    if json_path.exists():
        try:
            data = json.loads(json_path.read_text())
            if isinstance(data, list) and data:
                json_ids = [str(r.get("employee_id", "")).strip() or str(i + 1) for i, r in enumerate(data) if isinstance(r, dict)]
        except Exception:
            pass
    csv_path = DATA_DIR / "employees.csv"
    if csv_path.exists():
        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                rows = [r for r in csv_module.DictReader(f) if (r.get("employee_id") or "").strip()]
            if rows:
                csv_ids = [str(r["employee_id"]).strip() for r in rows]
        except Exception:
            pass
    # Prefer the list that matches batch count so IDs align with ciphertext order (e.g. 1001..1020 from CSV)
    if batch_count is not None:
        if json_ids is not None and len(json_ids) == batch_count:
            return json_ids
        if csv_ids is not None and len(csv_ids) == batch_count:
            return csv_ids
        return None
    return json_ids if json_ids else csv_ids


def _create_employees_from_batch_if_data(session_id: str) -> None:
    """If session has batch files and data/employees.json or employees.csv exists, create per-employee entries so GET .../employees returns them."""
    s = db.get_session(session_id)
    if not s:
        return
    blob_dir = _blob_dir(s)
    for name in ["salary.ct", "hours.ct", "bonus_points.ct"]:
        if not (blob_dir / name).exists():
            return
    try:
        salary_cts = _parse_batch_ct_file(blob_dir / "salary.ct")
        hours_cts = _parse_batch_ct_file(blob_dir / "hours.ct")
        bonus_cts = _parse_batch_ct_file(blob_dir / "bonus_points.ct")
    except Exception:
        return
    n = len(salary_cts)
    if len(hours_cts) != n or len(bonus_cts) != n:
        return
    # Use the file that has the same count as the batch so IDs match (e.g. 1001..1020 from CSV)
    ids = _load_employee_ids_from_data_dir(batch_count=n)
    if ids is None:
        ids = [str(i + 1) for i in range(n)]
    s.setdefault("employees", {})
    for i, eid in enumerate(ids):
        eid = (eid or "").strip()
        if not eid or not EMPLOYEE_ID_RE.match(eid):
            eid = str(i + 1)
        emp_dir = blob_dir / "employees" / eid
        emp_dir.mkdir(parents=True, exist_ok=True)
        _write_single_ct_bytes(emp_dir / "salary.ct", salary_cts[i])
        _write_single_ct_bytes(emp_dir / "hours.ct", hours_cts[i])
        _write_single_ct_bytes(emp_dir / "bonus_points.ct", bonus_cts[i])
        s["employees"][eid] = {
            "salary_ct_path": str(emp_dir / "salary.ct"),
            "hours_ct_path": str(emp_dir / "hours.ct"),
            "bonus_points_ct_path": str(emp_dir / "bonus_points.ct"),
        }
    s["updated_at"] = time.time()
    db.upsert_session(session_id, s)
    logger.info("Created %d employees for session %s (ids from data/employees.json or .csv matching batch count)", n, session_id)

def _parse_batch_ct_file(path: Path) -> list[bytes]:
    """Parse batch format [count: u32][len: u32][ct]...; return list of raw ct bytes."""
    data = path.read_bytes()
    if len(data) < 4:
        raise ValueError("batch ct file too short")
    (count,) = struct.unpack("<I", data[:4])
    out: list[bytes] = []
    offset = 4
    for _ in range(count):
        if offset + 4 > len(data):
            raise ValueError("batch ct file truncated")
        (ln,) = struct.unpack("<I", data[offset : offset + 4])
        offset += 4
        if offset + ln > len(data):
            raise ValueError("batch ct file truncated")
        out.append(bytes(data[offset : offset + ln]))
        offset += ln
    return out


def _write_single_ct(path: Path, ct_b64: str, field: str = "ciphertext_b64") -> None:
    """Write one ciphertext to file in format [count=1][len][bytes]. Uses _b64decode_safe for 400 on invalid base64."""
    raw = _b64decode_safe(ct_b64, field)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(struct.pack("<I", 1))
        f.write(struct.pack("<I", len(raw)))
        f.write(raw)


def _write_single_ct_bytes(path: Path, raw: bytes) -> None:
    """Write one ciphertext (raw bytes) to file in format [count=1][len][bytes]."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(struct.pack("<I", 1))
        f.write(struct.pack("<I", len(raw)))
        f.write(raw)


def _read_single_ct_bytes(path: Path) -> bytes:
    """Read one ciphertext from file format [count=1][len][ct]; return raw ct bytes."""
    data = path.read_bytes()
    if len(data) < 8:
        raise ValueError("ct file too short")
    (_, ln) = struct.unpack("<II", data[:8])
    if 8 + ln > len(data):
        raise ValueError("ct file truncated")
    return bytes(data[8 : 8 + ln])


@app.post("/v1/session/{session_id}/employees", tags=["employees"], response_model=CreateEmployeeResponse)
def create_or_update_employee(session_id: str, req: EmployeeDataRequest):
    """Create or replace one employee. Body: employee_id, salary_ct_b64, hours_ct_b64, bonus_points_ct_b64."""
    _validate_session_id(session_id)
    _validate_employee_id(req.employee_id)
    s = get_session(session_id)
    blob_dir = _blob_dir(s)
    if not (blob_dir / "params.seal").exists():
        raise HTTPException(status_code=400, detail="Session keys missing; upload keys first")
    emp_dir = blob_dir / "employees" / req.employee_id
    emp_dir.mkdir(parents=True, exist_ok=True)
    _write_single_ct(emp_dir / "salary.ct", req.salary_ct_b64, "salary_ct_b64")
    _write_single_ct(emp_dir / "hours.ct", req.hours_ct_b64, "hours_ct_b64")
    _write_single_ct(emp_dir / "bonus_points.ct", req.bonus_points_ct_b64, "bonus_points_ct_b64")
    s.setdefault("employees", {})
    s["employees"][req.employee_id] = {
        "salary_ct_path": str(emp_dir / "salary.ct"),
        "hours_ct_path": str(emp_dir / "hours.ct"),
        "bonus_points_ct_path": str(emp_dir / "bonus_points.ct"),
    }
    s["updated_at"] = time.time()
    db.upsert_session(session_id, s)
    return {"ok": True, "employee_id": req.employee_id}


@app.post("/v1/session/{session_id}/employees/plain", tags=["employees"], response_model=CreateEmployeeResponse)
def create_or_update_employee_plain(session_id: str, req: EmployeePlainRequest):
    """Create or replace one employee with plain values. Send employee_id, salary_cents, hours, bonus_points (no base64). Server encrypts and stores."""
    _validate_session_id(session_id)
    _validate_employee_id(req.employee_id)
    s = get_session(session_id)
    blob_dir = _blob_dir(s)
    if not (blob_dir / "params.seal").exists():
        raise HTTPException(status_code=400, detail="Session keys missing; upload keys first")
    try:
        body = _he_encrypt_employee_body(blob_dir, req.employee_id, req.salary_cents, req.hours, req.bonus_points)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    emp_dir = blob_dir / "employees" / req.employee_id
    emp_dir.mkdir(parents=True, exist_ok=True)
    _write_single_ct(emp_dir / "salary.ct", body["salary_ct_b64"], "salary_ct_b64")
    _write_single_ct(emp_dir / "hours.ct", body["hours_ct_b64"], "hours_ct_b64")
    _write_single_ct(emp_dir / "bonus_points.ct", body["bonus_points_ct_b64"], "bonus_points_ct_b64")
    s.setdefault("employees", {})
    s["employees"][req.employee_id] = {
        "salary_ct_path": str(emp_dir / "salary.ct"),
        "hours_ct_path": str(emp_dir / "hours.ct"),
        "bonus_points_ct_path": str(emp_dir / "bonus_points.ct"),
    }
    s["updated_at"] = time.time()
    db.upsert_session(session_id, s)
    return {"ok": True, "employee_id": req.employee_id}


@app.post("/v1/session/{session_id}/employees/from-batch", tags=["employees"])
def employees_from_batch(session_id: str, req: FromBatchRequest | None = Body(None)):
    """Create per-employee entries from this session's batch data (salary.ct, hours.ct, bonus_points.ct). Call after session/data or Run All. GET .../employees will then return these ids. Optional body: {\"employee_ids\": [\"1001\", \"1002\", ...]} (order = batch order; omit to use \"1\", \"2\", ... \"N\")."""
    _validate_session_id(session_id)
    s = get_session(session_id)
    blob_dir = _blob_dir(s)
    for name in ["salary.ct", "hours.ct", "bonus_points.ct"]:
        if not (blob_dir / name).exists():
            raise HTTPException(status_code=400, detail=f"Batch data missing: {name}. Upload session/data or use Run All first.")
    salary_cts = _parse_batch_ct_file(blob_dir / "salary.ct")
    hours_cts = _parse_batch_ct_file(blob_dir / "hours.ct")
    bonus_cts = _parse_batch_ct_file(blob_dir / "bonus_points.ct")
    n = len(salary_cts)
    if len(hours_cts) != n or len(bonus_cts) != n:
        raise HTTPException(status_code=400, detail="Batch files have different counts")
    ids = (req.employee_ids if req and req.employee_ids else None) or [str(i + 1) for i in range(n)]
    if len(ids) != n:
        raise HTTPException(status_code=400, detail=f"employee_ids length must be {n}")
    s.setdefault("employees", {})
    for i, eid in enumerate(ids):
        _validate_employee_id(eid)
        emp_dir = blob_dir / "employees" / eid
        emp_dir.mkdir(parents=True, exist_ok=True)
        _write_single_ct_bytes(emp_dir / "salary.ct", salary_cts[i])
        _write_single_ct_bytes(emp_dir / "hours.ct", hours_cts[i])
        _write_single_ct_bytes(emp_dir / "bonus_points.ct", bonus_cts[i])
        s["employees"][eid] = {
            "salary_ct_path": str(emp_dir / "salary.ct"),
            "hours_ct_path": str(emp_dir / "hours.ct"),
            "bonus_points_ct_path": str(emp_dir / "bonus_points.ct"),
        }
    s["updated_at"] = time.time()
    db.upsert_session(session_id, s)
    return {"created": n, "employee_ids": ids}


@app.get("/v1/session/{session_id}/employees", tags=["employees"], response_model=ListEmployeesResponse)
def list_employees(session_id: str):
    """List employee_ids and count for this session. Only includes employees added via POST .../employees; batch upload (session/data or Run All) does not add entries here."""
    s = get_session(session_id)
    emp = s.get("employees") or {}
    return {"employee_ids": list(emp.keys()), "count": len(emp)}


@app.get("/v1/session/{session_id}/employees/{employee_id}", tags=["employees"], response_model=GetEmployeeResponse)
def get_employee(session_id: str, employee_id: str):
    """Get one employee's encrypted payload. Returns salary_ct_b64, hours_ct_b64, bonus_points_ct_b64."""
    _validate_employee_id(employee_id)
    s = get_session(session_id)
    blob_dir = _blob_dir(s)
    emp = (s.get("employees") or {}).get(employee_id)
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    # Each file is [1][len][ct]; return the single ct as b64
    def read_one_ct(path_key: str) -> str:
        p = Path(emp[path_key])
        if not p.exists():
            raise HTTPException(status_code=500, detail=f"Missing {path_key}")
        data = p.read_bytes()
        if len(data) < 8:
            raise HTTPException(status_code=500, detail="Invalid ct file")
        (_, ln) = struct.unpack("<II", data[:8])
        if 8 + ln > len(data):
            raise HTTPException(status_code=500, detail="Invalid ct file")
        return base64.b64encode(data[8 : 8 + ln]).decode("ascii")
    return {
        "employee_id": employee_id,
        "salary_ct_b64": read_one_ct("salary_ct_path"),
        "hours_ct_b64": read_one_ct("hours_ct_path"),
        "bonus_points_ct_b64": read_one_ct("bonus_points_ct_path"),
    }


def _resolve_delta_ct(blob_dir: Path, plain_delta: int | None, delta_b64: str | None, field: str) -> bytes | None:
    """Return delta ciphertext bytes: from plain_delta (encrypt) or from delta_b64 (decode). None if both omitted."""
    if plain_delta is not None:
        try:
            return _he_encrypt_one_plaintext(blob_dir, plain_delta)
        except RuntimeError as e:
            raise HTTPException(status_code=503, detail=str(e))
    if delta_b64:
        return _b64decode_safe(delta_b64, field)
    return None


@app.patch("/v1/session/{session_id}/employees/{employee_id}/adjust", tags=["employees"], response_model=CreateEmployeeResponse)
def adjust_employee(session_id: str, employee_id: str, req: AdjustEmployeeRequest):
    """Add deltas to this employee's salary, hours, bonus_points. Send plain ints (salary_delta, hours_delta, bonus_points_delta) and server encrypts; or send *_delta_ct_b64. Send only the fields you want to change."""
    _validate_session_id(session_id)
    _validate_employee_id(employee_id)
    has_any = (
        req.salary_delta is not None or req.salary_delta_ct_b64
        or req.hours_delta is not None or req.hours_delta_ct_b64
        or req.bonus_points_delta is not None or req.bonus_points_delta_ct_b64
    )
    if not has_any:
        raise HTTPException(status_code=400, detail="Send at least one of salary_delta, hours_delta, bonus_points_delta (or *_delta_ct_b64)")
    s = get_session(session_id)
    blob_dir = _blob_dir(s)
    emp = (s.get("employees") or {}).get(employee_id)
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    if not (blob_dir / "params.seal").exists():
        raise HTTPException(status_code=400, detail="Session keys missing")
    emp_dir = Path(emp["salary_ct_path"]).parent
    for path_key, plain_delta, delta_b64, field in [
        ("salary_ct_path", req.salary_delta, req.salary_delta_ct_b64, "salary_delta_ct_b64"),
        ("hours_ct_path", req.hours_delta, req.hours_delta_ct_b64, "hours_delta_ct_b64"),
        ("bonus_points_ct_path", req.bonus_points_delta, req.bonus_points_delta_ct_b64, "bonus_points_delta_ct_b64"),
    ]:
        delta_ct = _resolve_delta_ct(blob_dir, plain_delta, delta_b64, field)
        if delta_ct is None:
            continue
        ct_path = Path(emp[path_key])
        if not ct_path.exists():
            raise HTTPException(status_code=500, detail=f"Missing {path_key}")
        try:
            current_ct = _read_single_ct_bytes(ct_path)
            result_ct = _he_add_two_ciphertexts(blob_dir, current_ct, delta_ct)
            _write_single_ct_bytes(ct_path, result_ct)
        except Exception as e:
            logger.exception("adjust %s failed: %s", path_key, e)
            raise HTTPException(status_code=500, detail=str(e))
    s["updated_at"] = time.time()
    db.upsert_session(session_id, s)
    return {"ok": True, "employee_id": employee_id}


@app.put("/v1/session/{session_id}/employees/{employee_id}", tags=["employees"], response_model=CreateEmployeeResponse)
def update_employee(session_id: str, employee_id: str, req: EmployeeDataRequest):
    """Update employee. Path and body employee_id must match."""
    _validate_employee_id(employee_id)
    if req.employee_id != employee_id:
        raise HTTPException(status_code=400, detail="employee_id in path and body must match")
    return create_or_update_employee(session_id, req)


@app.delete("/v1/session/{session_id}/employees/{employee_id}", tags=["employees"], response_model=DeleteEmployeeResponse)
def delete_employee(session_id: str, employee_id: str):
    """Remove one employee's encrypted data from the session."""
    _validate_employee_id(employee_id)
    s = get_session(session_id)
    emp = s.get("employees") or {}
    if employee_id not in emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    blob_dir = _blob_dir(s)
    emp_dir = blob_dir / "employees" / employee_id
    if emp_dir.exists():
        shutil.rmtree(emp_dir)
    del s["employees"][employee_id]
    s["updated_at"] = time.time()
    db.upsert_session(session_id, s)
    return {"ok": True, "employee_id": employee_id}


def _enqueue_compute(session_id: str, op: str, result_type: str, **extra) -> str:
    job_id = str(uuid.uuid4())
    s = get_session(session_id)
    blob_dir = _blob_dir(s)
    job_dir = db.job_blob_dir(job_id)
    for name in ["params.seal", "relin_keys.seal", "public_key.seal"]:
        src = blob_dir / name
        if src.exists():
            shutil.copy2(src, job_dir / name)
    try:
        count = _prepare_compute_input(s, blob_dir, job_dir, op)
    except HTTPException:
        raise
    created_at = time.time()
    db.upsert_job(job_id, {
        "job_id": job_id,
        "session_id": session_id,
        "status": "running",
        "result_path": None,
        "result_type": result_type,
        "count": count,
        "created_at": created_at,
        "finished_at": None,
        **{k: v for k, v in extra.items() if k != "worker_extra"},
    })
    try:
        result_path = _run_compute(op, job_dir)
        # Store path relative to DATA_DIR for portability
        try:
            result_path_str = str(result_path.relative_to(DATA_DIR))
        except ValueError:
            result_path_str = str(result_path)
        finished_at = time.time()
        db.upsert_job(job_id, {
            "job_id": job_id,
            "session_id": session_id,
            "status": "done",
            "result_path": result_path_str,
            "result_type": result_type,
            "count": count,
            "created_at": created_at,
            "finished_at": finished_at,
            **{k: v for k, v in extra.items() if k != "worker_extra"},
        })
    except Exception as e:
        db.upsert_job(job_id, {
            "job_id": job_id,
            "session_id": session_id,
            "status": "error",
            "error": str(e),
            "result_type": result_type,
            "created_at": created_at,
            "finished_at": time.time(),
        })
        raise HTTPException(status_code=500, detail=str(e))
    return job_id


@app.post("/v1/compute/total_payroll", tags=["compute"], response_model=ComputeJobResponse)
def compute_total_payroll(req: ComputeSessionRequest):
    """Run total_payroll (sum of salaries). Returns job_id; get result with GET /v1/result/{job_id}."""
    job_id = _enqueue_compute(req.session_id, "total_payroll", "total_payroll")
    return {"job_id": job_id}


@app.post("/v1/compute/avg_salary", tags=["compute"], response_model=ComputeJobResponse)
def compute_avg_salary(req: ComputeSessionRequest):
    """Run avg_salary (encrypted sum + count). Returns job_id and count; decrypt then divide sum/count locally."""
    s = get_session(req.session_id)
    job_id = _enqueue_compute(req.session_id, "avg_salary", "avg_salary")
    count = len(s.get("employees")) if s.get("employees") else s.get("count", 0)
    return {"job_id": job_id, "count": count}


@app.post("/v1/compute/total_hours", tags=["compute"], response_model=ComputeJobResponse)
def compute_total_hours(req: ComputeSessionRequest):
    """Run total_hours (sum of hours). Returns job_id."""
    job_id = _enqueue_compute(req.session_id, "total_hours", "total_hours")
    return {"job_id": job_id}


@app.post("/v1/compute/bonus_pool", tags=["compute"], response_model=ComputeJobResponse)
def compute_bonus_pool(req: BonusPoolRequest):
    """Run bonus_pool (encrypted sum of salaries). Decrypt then compute sum * bonus_rate_bps / 10000 locally."""
    job_id = _enqueue_compute(
        req.session_id, "bonus_pool", "bonus_pool",
        bonus_rate_bps=req.bonus_rate_bps,
    )
    return {"job_id": job_id, "bonus_rate_bps": req.bonus_rate_bps}


@app.get("/v1/result/{job_id}", tags=["results"], response_model=ResultResponse)
def get_result(job_id: str):
    """Get job result. Returns result_ciphertext_b64; decrypt locally with secret key."""
    j = db.get_job(job_id)
    if not j:
        raise HTTPException(status_code=404, detail="Job not found")
    if j["status"] == "error":
        raise HTTPException(status_code=500, detail=j.get("error", "Unknown error"))
    if j["status"] == "running":
        raise HTTPException(status_code=409, detail="Job still running")
    # status == "done": read result from file (path may be relative to DATA_DIR)
    result_path = j.get("result_path")
    if not result_path:
        raise HTTPException(status_code=500, detail="Result file missing")
    result_full = (DATA_DIR / result_path) if not Path(result_path).is_absolute() else Path(result_path)
    if not result_full.exists():
        raise HTTPException(status_code=500, detail="Result file missing")
    result_b64 = base64.b64encode(result_full.read_bytes()).decode("ascii")
    return {
        "job_id": job_id,
        "status": j["status"],
        "result_ciphertext_b64": result_b64,
        "result_type": j["result_type"],
        "count": j.get("count"),
        "bonus_rate_bps": j.get("bonus_rate_bps"),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
