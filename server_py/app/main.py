"""
HomoLock-HR FastAPI server.
Uses file-based storage (JSON + blob files) for sessions and jobs; runs C++ worker via subprocess.
Secret key is NEVER stored or logged.
"""

import base64
import logging
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.storage.file_db import FileDB

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="HomoLock-HR", version="0.1.0")

# File-based storage: base dir from env (default ./data relative to cwd)
DATA_DIR = Path(os.environ.get("HOMOLOCK_DATA_DIR", "data")).resolve()
db = FileDB(DATA_DIR)

# Path to C++ worker binary (env or relative to server_py)
def _worker_bin() -> str:
    if os.environ.get("HOMOLOCK_WORKER"):
        return os.environ["HOMOLOCK_WORKER"]
    base = Path(__file__).resolve().parent.parent
    return str(base / "cpp_worker" / "build" / "homolock_worker")


WORKER_BIN = _worker_bin()

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_session(session_id: str) -> dict:
    """Return session doc from FileDB; 404 if not found."""
    _validate_session_id(session_id)
    s = db.get_session(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    return s


def run_worker(op: str, work_dir: Path, extra: list[str] | None = None) -> Path:
    """Run homolock_worker in work_dir; return path to result.ct. Worker expects params.seal, relin_keys.seal, public_key.seal, and salary.ct or hours.ct."""
    result_ct = work_dir / "result.ct"
    cmd = [
        WORKER_BIN,
        "--op", op,
        "--params", str(work_dir / "params.seal"),
        "--relin", str(work_dir / "relin_keys.seal"),
        "--pk", str(work_dir / "public_key.seal"),
        "--out", str(result_ct),
    ]
    if op in ("total_payroll", "avg_salary", "bonus_pool"):
        cmd += ["--in", str(work_dir / "salary.ct")]
    elif op == "total_hours":
        cmd += ["--in", str(work_dir / "hours.ct")]
    else:
        raise ValueError(f"Unknown op: {op}")
    if extra:
        cmd += extra
    logger.info("Running worker (op=%s, cwd=%s)", op, work_dir)
    proc = subprocess.run(cmd, cwd=work_dir, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        logger.error("Worker stderr: %s", proc.stderr)
        raise HTTPException(status_code=500, detail=f"Worker failed: {proc.stderr or proc.stdout}")
    if not result_ct.exists():
        raise HTTPException(status_code=500, detail="Worker did not produce result.ct")
    return result_ct


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
    s["updated_at"] = now
    db.upsert_session(req.session_id, s)
    return {"ok": True}


def _enqueue_compute(session_id: str, op: str, result_type: str, **extra) -> str:
    job_id = str(uuid.uuid4())
    s = get_session(session_id)
    blob_dir = Path(s["blob_dir"])
    # Require data artifacts for compute
    if not (blob_dir / "salary.ct").exists() or not (blob_dir / "hours.ct").exists():
        raise HTTPException(status_code=400, detail="Session data missing; upload ciphertexts first")
    job_dir = db.job_blob_dir(job_id)
    job_dir = job_dir.resolve()
    # Copy inputs into job dir so worker can run in job_dir
    for name in ["params.seal", "relin_keys.seal", "public_key.seal"]:
        src = blob_dir / name
        if src.exists():
            shutil.copy2(src, job_dir / name)
    if op in ("total_payroll", "avg_salary", "bonus_pool"):
        shutil.copy2(blob_dir / "salary.ct", job_dir / "salary.ct")
    else:
        shutil.copy2(blob_dir / "hours.ct", job_dir / "hours.ct")
    created_at = time.time()
    db.upsert_job(job_id, {
        "job_id": job_id,
        "session_id": session_id,
        "status": "running",
        "result_path": None,
        "result_type": result_type,
        "count": s.get("count"),
        "created_at": created_at,
        "finished_at": None,
        **{k: v for k, v in extra.items() if k != "worker_extra"},
    })
    try:
        result_path = run_worker(op, job_dir, extra=list(extra.get("worker_extra", [])))
        result_path_str = str(result_path.resolve())
        finished_at = time.time()
        db.upsert_job(job_id, {
            "job_id": job_id,
            "session_id": session_id,
            "status": "done",
            "result_path": result_path_str,
            "result_type": result_type,
            "count": s.get("count"),
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
    return {"job_id": job_id, "count": s["count"]}


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
