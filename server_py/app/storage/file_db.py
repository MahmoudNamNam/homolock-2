"""
File-based "database" for HomoLock-HR server.
Single unified directory under base_dir:
- base_dir/sessions.json, base_dir/jobs.json  -> metadata
- base_dir/sessions/<session_id>/  -> params, keys, ciphertexts
- base_dir/jobs/<job_id>/          -> result.ct and inputs
- Atomic writes: write to temp file then rename.
- File locking via portalocker for safe concurrent access (Linux/Windows).
"""

import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

import portalocker

logger = logging.getLogger(__name__)

# All under one base_dir (no db/ or blobs/ split)
DB_LOCK_NAME = ".db.lock"
SESSIONS_JSON = "sessions.json"
JOBS_JSON = "jobs.json"
SESSIONS_DIR = "sessions"
JOBS_DIR = "jobs"


def read_json(path: Path) -> dict[str, Any]:
    """Read a JSON file. Returns empty dict if file does not exist."""
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    """
    Write JSON atomically: write to a temp file in the same directory, then rename.
    Caller must hold the DB lock when calling this for read-modify-write consistency.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp." + str(os.getpid()))
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        tmp_path.replace(path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass


class FileDB:
    """
    File-based storage for sessions and jobs (unified under base_dir).
    - base_dir/sessions.json  -> { session_id: session_doc }
    - base_dir/jobs.json      -> { job_id: job_doc }
    - base_dir/sessions/<session_id>/  -> params.seal, public_key.seal, etc.
    - base_dir/jobs/<job_id>/          -> result.ct (and copied inputs for worker run)
    """

    def __init__(self, base_dir: str | Path):
        self.base = Path(base_dir)
        self.sessions_path = self.base / SESSIONS_JSON
        self.jobs_path = self.base / JOBS_JSON
        self.sessions_root = self.base / SESSIONS_DIR
        self.jobs_root = self.base / JOBS_DIR
        self.base.mkdir(parents=True, exist_ok=True)
        self.sessions_root.mkdir(parents=True, exist_ok=True)
        self.jobs_root.mkdir(parents=True, exist_ok=True)
        self._migrate_from_legacy_layout()

    def _migrate_from_legacy_layout(self) -> None:
        """One-time: move db/ and blobs/ into unified base_dir layout."""
        old_db = self.base / "db"
        old_blobs = self.base / "blobs"
        if not old_db.exists() and not old_blobs.exists():
            return
        # Migrate JSON from db/ to base/
        if old_db.exists():
            for name in (SESSIONS_JSON, JOBS_JSON):
                src = old_db / name
                dst = self.base / name
                if src.exists() and not dst.exists():
                    data = read_json(src)
                    # Rewrite paths: blobs/sessions/ -> sessions/, blobs/jobs/ -> jobs/
                    if name == SESSIONS_JSON:
                        for doc in data.values():
                            if isinstance(doc.get("blob_dir"), str) and doc["blob_dir"].startswith("blobs/sessions/"):
                                doc["blob_dir"] = "sessions/" + doc["blob_dir"].split("blobs/sessions/", 1)[1]
                    elif name == JOBS_JSON:
                        for doc in data.values():
                            if isinstance(doc.get("result_path"), str) and "blobs/jobs/" in doc["result_path"]:
                                doc["result_path"] = doc["result_path"].replace("blobs/jobs/", "jobs/", 1)
                    write_json_atomic(dst, data)
                    logger.info("Migrated %s -> %s", src, dst)
        # Move blobs/sessions/* to sessions/, blobs/jobs/* to jobs/
        if old_blobs.exists():
            for legacy_sub, new_root in [("sessions", self.sessions_root), ("jobs", self.jobs_root)]:
                src_root = old_blobs / legacy_sub
                if not src_root.exists():
                    continue
                for entry in src_root.iterdir():
                    if entry.is_dir():
                        dst = new_root / entry.name
                        if not dst.exists():
                            shutil.copytree(entry, dst)
                            logger.info("Migrated %s -> %s", entry, dst)
                        else:
                            for f in entry.rglob("*"):
                                if f.is_file():
                                    rel = f.relative_to(entry)
                                    (dst / rel).parent.mkdir(parents=True, exist_ok=True)
                                    shutil.copy2(f, dst / rel)

    def _lock_and_read_sessions(self) -> dict[str, Any]:
        lock_path = self.base / DB_LOCK_NAME
        with portalocker.Lock(lock_path, "wb", timeout=10):
            return read_json(self.sessions_path)

    def _lock_and_read_jobs(self) -> dict[str, Any]:
        lock_path = self.base / DB_LOCK_NAME
        with portalocker.Lock(lock_path, "wb", timeout=10):
            return read_json(self.jobs_path)

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Return session doc or None if not found."""
        data = self._lock_and_read_sessions()
        return data.get(session_id)

    def upsert_session(self, session_id: str, session_doc: dict[str, Any]) -> None:
        """Insert or update session document."""
        lock_path = self.base / DB_LOCK_NAME
        with portalocker.Lock(lock_path, "wb", timeout=10):
            data = read_json(self.sessions_path)
            data[session_id] = session_doc
            write_json_atomic(self.sessions_path, data)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        """Return job doc or None if not found."""
        data = self._lock_and_read_jobs()
        return data.get(job_id)

    def upsert_job(self, job_id: str, job_doc: dict[str, Any]) -> None:
        """Insert or update job document."""
        lock_path = self.base / DB_LOCK_NAME
        with portalocker.Lock(lock_path, "wb", timeout=10):
            data = read_json(self.jobs_path)
            data[job_id] = job_doc
            write_json_atomic(self.jobs_path, data)

    def list_jobs(self, session_id: str) -> list[dict[str, Any]]:
        """Return all jobs for a session (optional)."""
        data = self._lock_and_read_jobs()
        return [v for v in data.values() if v.get("session_id") == session_id]

    def session_blob_dir(self, session_id: str) -> Path:
        """Path to sessions/<session_id>/ (created on first use)."""
        p = self.sessions_root / session_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    def job_blob_dir(self, job_id: str) -> Path:
        """Path to jobs/<job_id>/ (created on first use)."""
        p = self.jobs_root / job_id
        p.mkdir(parents=True, exist_ok=True)
        return p
