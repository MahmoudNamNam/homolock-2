"""
HomoLock-HR FastAPI server.
File-based storage (JSON + blobs). HE via Python (PySEAL) only. CRUD on encrypted HR employee data.
Secret key is NEVER stored or logged.
"""

import base64
import logging
import os
import re
import shutil
import struct
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.storage.file_db import FileDB
from app.he_engine import is_available as _he_available, run_sum as _he_run_sum

# Lazy alias so we can use he_engine.is_available / he_engine.run_sum
class _HeEngine:
    is_available = staticmethod(_he_available)
    run_sum = staticmethod(_he_run_sum)


he_engine = _HeEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="HomoLock-HR", version="0.1.0")

# File-based storage: base dir from env (default ./data relative to cwd)
DATA_DIR = Path(os.environ.get("HOMOLOCK_DATA_DIR", "data")).resolve()
db = FileDB(DATA_DIR)

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


def _run_compute(op: str, work_dir: Path) -> Path:
    """Run HE sum via Python (PySEAL). Returns path to result.ct."""
    if not he_engine.is_available():
        raise HTTPException(
            status_code=503,
            detail="HE engine unavailable. Install PySEAL (e.g. Huelse/SEAL-Python) so the server can run homomorphic computations.",
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

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/session/keys")
def session_keys(req: SessionKeysRequest):
    _validate_session_id(req.session_id)
    blob_dir = db.session_blob_dir(req.session_id)
    blob_dir = blob_dir.resolve()
    # Write keys to blob dir (never log key/ciphertext contents)
    (blob_dir / "params.seal").write_bytes(base64.b64decode(req.params_b64))
    (blob_dir / "public_key.seal").write_bytes(base64.b64decode(req.public_key_b64))
    (blob_dir / "relin_keys.seal").write_bytes(base64.b64decode(req.relin_keys_b64))
    if req.galois_keys_b64:
        (blob_dir / "galois_keys.seal").write_bytes(base64.b64decode(req.galois_keys_b64))
    now = time.time()
    session_doc = {
        "session_id": req.session_id,
        "blob_dir": str(blob_dir),
        "params_path": str(blob_dir / "params.seal"),
        "public_key_path": str(blob_dir / "public_key.seal"),
        "relin_keys_path": str(blob_dir / "relin_keys.seal"),
        "salary_ct_path": None,
        "hours_ct_path": None,
        "bonus_points_ct_path": None,
        "count": 0,
        "employees": {},
        "created_at": now,
        "updated_at": now,
    }
    db.upsert_session(req.session_id, session_doc)
    logger.info("Session created: %s", req.session_id)
    return {"ok": True}


@app.post("/v1/session/data")
def session_data(req: SessionDataRequest):
    s = get_session(req.session_id)
    blob_dir = Path(s["blob_dir"])
    # Ensure session has keys (required before data)
    if not (blob_dir / "params.seal").exists():
        raise HTTPException(status_code=400, detail="Session keys missing; upload keys first")
    (blob_dir / "salary.ct").write_bytes(base64.b64decode(req.salary_ct_b64))
    (blob_dir / "hours.ct").write_bytes(base64.b64decode(req.hours_ct_b64))
    (blob_dir / "bonus_points.ct").write_bytes(base64.b64decode(req.bonus_points_ct_b64))
    now = time.time()
    s["salary_ct_path"] = str(blob_dir / "salary.ct")
    s["hours_ct_path"] = str(blob_dir / "hours.ct")
    s["bonus_points_ct_path"] = str(blob_dir / "bonus_points.ct")
    s["count"] = req.count
    s.setdefault("employees", {})
    s["updated_at"] = now
    db.upsert_session(req.session_id, s)
    return {"ok": True}


# ---------- CRUD: HR employees (encrypted per employee) ----------

def _write_single_ct(path: Path, ct_b64: str) -> None:
    """Write one ciphertext to file in format [count=1][len][bytes]."""
    raw = base64.b64decode(ct_b64)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(struct.pack("<I", 1))
        f.write(struct.pack("<I", len(raw)))
        f.write(raw)


@app.post("/v1/session/{session_id}/employees")
def create_or_update_employee(session_id: str, req: EmployeeDataRequest):
    """Create or replace one employee's encrypted HR data (salary, hours, bonus_points)."""
    _validate_session_id(session_id)
    _validate_employee_id(req.employee_id)
    s = get_session(session_id)
    blob_dir = Path(s["blob_dir"])
    if not (blob_dir / "params.seal").exists():
        raise HTTPException(status_code=400, detail="Session keys missing; upload keys first")
    emp_dir = blob_dir / "employees" / req.employee_id
    emp_dir.mkdir(parents=True, exist_ok=True)
    _write_single_ct(emp_dir / "salary.ct", req.salary_ct_b64)
    _write_single_ct(emp_dir / "hours.ct", req.hours_ct_b64)
    _write_single_ct(emp_dir / "bonus_points.ct", req.bonus_points_ct_b64)
    s.setdefault("employees", {})
    s["employees"][req.employee_id] = {
        "salary_ct_path": str(emp_dir / "salary.ct"),
        "hours_ct_path": str(emp_dir / "hours.ct"),
        "bonus_points_ct_path": str(emp_dir / "bonus_points.ct"),
    }
    s["updated_at"] = time.time()
    db.upsert_session(session_id, s)
    return {"ok": True, "employee_id": req.employee_id}


@app.get("/v1/session/{session_id}/employees")
def list_employees(session_id: str):
    """List employee_ids in this session."""
    s = get_session(session_id)
    emp = s.get("employees") or {}
    return {"employee_ids": list(emp.keys()), "count": len(emp)}


@app.get("/v1/session/{session_id}/employees/{employee_id}")
def get_employee(session_id: str, employee_id: str):
    """Get one employee's encrypted payload (base64 ciphertexts). Client decrypts with secret key."""
    _validate_employee_id(employee_id)
    s = get_session(session_id)
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


@app.put("/v1/session/{session_id}/employees/{employee_id}")
def update_employee(session_id: str, employee_id: str, req: EmployeeDataRequest):
    """Update employee; employee_id in path must match body."""
    _validate_employee_id(employee_id)
    if req.employee_id != employee_id:
        raise HTTPException(status_code=400, detail="employee_id in path and body must match")
    return create_or_update_employee(session_id, req)


@app.delete("/v1/session/{session_id}/employees/{employee_id}")
def delete_employee(session_id: str, employee_id: str):
    """Remove one employee's encrypted data."""
    _validate_employee_id(employee_id)
    s = get_session(session_id)
    emp = s.get("employees") or {}
    if employee_id not in emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    blob_dir = Path(s["blob_dir"])
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
    blob_dir = Path(s["blob_dir"])
    job_dir = db.job_blob_dir(job_id)
    job_dir = job_dir.resolve()
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
        result_path_str = str(result_path.resolve())
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


@app.post("/v1/compute/total_payroll")
def compute_total_payroll(req: ComputeSessionRequest):
    job_id = _enqueue_compute(req.session_id, "total_payroll", "total_payroll")
    return {"job_id": job_id}


@app.post("/v1/compute/avg_salary")
def compute_avg_salary(req: ComputeSessionRequest):
    s = get_session(req.session_id)
    job_id = _enqueue_compute(req.session_id, "avg_salary", "avg_salary")
    count = len(s.get("employees")) if s.get("employees") else s.get("count", 0)
    return {"job_id": job_id, "count": count}


@app.post("/v1/compute/total_hours")
def compute_total_hours(req: ComputeSessionRequest):
    job_id = _enqueue_compute(req.session_id, "total_hours", "total_hours")
    return {"job_id": job_id}


@app.post("/v1/compute/bonus_pool")
def compute_bonus_pool(req: BonusPoolRequest):
    job_id = _enqueue_compute(
        req.session_id, "bonus_pool", "bonus_pool",
        bonus_rate_bps=req.bonus_rate_bps,
    )
    return {"job_id": job_id, "bonus_rate_bps": req.bonus_rate_bps}


@app.get("/v1/result/{job_id}")
def get_result(job_id: str):
    j = db.get_job(job_id)
    if not j:
        raise HTTPException(status_code=404, detail="Job not found")
    if j["status"] == "error":
        raise HTTPException(status_code=500, detail=j.get("error", "Unknown error"))
    if j["status"] == "running":
        raise HTTPException(status_code=409, detail="Job still running")
    # status == "done": read result from file
    result_path = j.get("result_path")
    if not result_path or not Path(result_path).exists():
        raise HTTPException(status_code=500, detail="Result file missing")
    result_b64 = base64.b64encode(Path(result_path).read_bytes()).decode("ascii")
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
