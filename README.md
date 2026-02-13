# HomoLock-HR

Privacy-preserving HR/Payroll computations using **Homomorphic Encryption (HE)**. Employees’ sensitive values (salary, hours, bonus inputs) are encrypted on the **client**; the **cloud server** computes on ciphertext **without ever decrypting** and never receives the secret key.

## Overview

- **Client**: C++ CLI (`client_cpp/`) — key generation, encryption, upload, and decryption of results.
- **Server**: Python FastAPI (`server_py/`) — receives public/evaluation keys and ciphertexts; runs C++ worker for HE operations.
- **Worker**: C++ binary (`server_py/cpp_worker/`) — performs BFV homomorphic sums (no secret key).

### Cryptography (MVP)

- **Scheme**: Microsoft SEAL **BFV** (integer arithmetic). Salary and hours are integers (e.g. salary in cents/halalas/piasters).
- **Secure computations (server-side on ciphertext)**:
  1. **Total payroll** — sum of salaries.
  2. **Average salary** — server returns encrypted sum + plaintext count; client decrypts and divides locally.
  3. **Total hours** — sum of hours.
  4. **Bonus pool** — server returns encrypted sum(salary); client computes `bonus_pool = sum * BONUS_RATE_BPS / 10000` after decryption (division is client-side).

### Threat model

- **Honest-but-curious server**: follows the protocol but must not learn individual salaries/hours.
- **Secret key (SK)** is only on the client. Server may hold: public key (PK), relinearization keys, and (optionally) Galois keys. **SK must never be uploaded.**

### Key types

| Key           | Who has it   | Purpose                          |
|---------------|--------------|-----------------------------------|
| Secret key    | Client only  | Decrypt ciphertexts              |
| Public key    | Client + Server | Encrypt; server does not need to encrypt in MVP |
| Relin keys    | Client + Server | Relinearize after multiplications (MVP uses only sums) |
| Galois keys   | Client + Server | Slot rotations (optional; MVP uses add-many, no rotation) |

---

## Build & Run (Ubuntu 22.04)

### Prerequisites

- CMake ≥ 3.16, GCC with C++17
- libcurl: `sudo apt install libcurl4-openssl-dev`
- Python 3.10+, pip

### 1. C++ client

```bash
cd client_cpp
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build . -j
# Binary: build/homolock_client
```

### 2. C++ worker (used by server)

```bash
cd server_py/cpp_worker
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build . -j
# Binary: build/homolock_worker
```

**Note (macOS / CMake 4+):** If you see *"Compatibility with CMake < 3.5 has been removed"* when building SEAL’s zlib, pass `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` as above. There is no need to install a separate `cmake@3.30` (Homebrew does not provide that formula).

### 3. Python server

```bash
cd server_py
pip install -r requirements.txt
# Optional: set worker path if not using default
export HOMOLOCK_WORKER=/path/to/server_py/cpp_worker/build/homolock_worker
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 4. Run tests (optional)

```bash
cd server_py
pip install -r requirements.txt
pytest tests/ -v
```

### 5. End-to-end demo

From repo root:

```bash
chmod +x demo.sh
./demo.sh
```

This will: build worker and client, start the server, run `init-context` → `keygen` → `encrypt-hr` → `upload-session` → `upload-data` → `compute` (all four jobs) → `fetch-and-decrypt` for each job and print decrypted results.

---

## Client CLI

| Command | Description |
|--------|-------------|
| `init-context [--poly 4096\|8192]` | Create `out/params.seal` (default poly=8192). |
| `keygen` | Generate secret/public/relin/galois keys under `out/`. **Never upload secret_key.seal.** |
| `encrypt-hr` | Read `data/employees.csv`; write `out/salary.ct`, `out/hours.ct`, `out/bonus_points.ct`, `out/meta.json`. |
| `upload-session [--server URL] [--session ID]` | POST keys to `/v1/session/keys`. |
| `upload-data --session ID [--server URL]` | POST ciphertexts to `/v1/session/data`. |
| `compute --session ID [--server URL] [--bonus-bps 1000]` | Trigger total_payroll, avg_salary, total_hours, bonus_pool; prints job_ids. |
| `fetch-and-decrypt --job-id ID [--server URL]` | GET result and decrypt; print value. |

Default server URL: `http://127.0.0.1:8000`.

---

## API (FastAPI)

- `GET /health` → `{"status":"ok"}`
- `POST /v1/session/keys` — body: `session_id`, `params_b64`, `public_key_b64`, `relin_keys_b64`, optional `galois_keys_b64`
- `POST /v1/session/data` — body: `session_id`, `salary_ct_b64`, `hours_ct_b64`, `bonus_points_ct_b64`, `count`
- `POST /v1/compute/total_payroll` — body: `session_id` → `job_id`
- `POST /v1/compute/avg_salary` — body: `session_id` → `job_id`, `count`
- `POST /v1/compute/total_hours` — body: `session_id` → `job_id`
- `POST /v1/compute/bonus_pool` — body: `session_id`, `bonus_rate_bps` → `job_id`, `bonus_rate_bps`
- `GET /v1/result/{job_id}` → `status`, `result_ciphertext_b64`, `result_type`, optional `count`, `bonus_rate_bps`

---

## How average is computed

- Server computes **encrypted sum(salary)** and returns that ciphertext plus **plaintext count**.
- Client decrypts to get the sum, then computes **average = sum / count** locally. Division is not done on ciphertext (BFV division is not supported in this MVP).

---

## File-based storage (JSON)

The server persists sessions and jobs on disk using **JSON metadata** and **blob files** (no MongoDB).

- **Config**: Set `HOMOLOCK_DATA_DIR` to the base directory (default: `./data` relative to the server process cwd).
- **Layout**:
  - `data/db/sessions.json` — session metadata (paths, count, timestamps); no raw keys/ciphertexts.
  - `data/db/jobs.json` — job metadata (status, result_path, result_type, count, etc.).
  - `data/blobs/sessions/<session_id>/` — params.seal, public_key.seal, relin_keys.seal, optional galois_keys.seal, then salary.ct, hours.ct, bonus_points.ct after data upload.
  - `data/blobs/jobs/<job_id>/` — copied inputs for the C++ worker and `result.ct` output.
- **Concurrency**: File locking (e.g. `portalocker`) is used when reading/writing the JSON DB so concurrent requests are safe.
- **Atomic writes**: JSON is written to a temp file then renamed so readers never see partial content.
- **Migration**: If you previously used the in-memory server, there is no migration path; start with an empty `HOMOLOCK_DATA_DIR` and re-upload keys and data per session.

---

## Limitations and future work

- **BFV**: Integer-only; no native real-number division on ciphertext. For reals, consider CKKS.
- **Packing**: MVP encrypts one value per ciphertext and uses add-many for sums; batching + rotations would reduce ciphertext count and bandwidth.
- **Storage**: Sessions and jobs are file-based (JSON + blobs); optional cleanup of old jobs; no auth.
- **Bonus pool**: Server returns encrypted sum(salary); client applies `bonus_rate_bps` and division after decryption.

---

## AWS EC2 (Ubuntu 22.04)

1. Launch Ubuntu 22.04; open port **8000** (TCP) in the security group.
2. Install: `sudo apt update && sudo apt install -y build-essential cmake libcurl4-openssl-dev python3-pip git`
3. Clone repo; build `client_cpp` and `server_py/cpp_worker` as above.
4. **Data directory**: Create a dedicated directory for server data and set permissions:
   ```bash
   sudo mkdir -p /var/lib/homolock
   sudo chown ubuntu:ubuntu /var/lib/homolock
   export HOMOLOCK_DATA_DIR=/var/lib/homolock
   ```
5. Run server (from `server_py`):
   ```bash
   cd server_py
   pip install -r requirements.txt
   export HOMOLOCK_WORKER=/path/to/server_py/cpp_worker/build/homolock_worker  # if needed
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```
   For production you can run with multiple workers, e.g. `uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2` (file locking keeps the JSON DB safe).
6. From your machine, use the client with `--server http://<EC2_PUBLIC_IP>:8000`.

Never upload `secret_key.seal` to the server or any untrusted host.
# homolock
# homolock-2
# homolock-2
