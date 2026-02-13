# HomoLock-HR

Privacy-preserving HR/Payroll computations using **Homomorphic Encryption (HE)**. Employees’ sensitive values (salary, hours, bonus inputs) are encrypted on the **client**; the **cloud server** computes on ciphertext **without ever decrypting** and never receives the secret key.

## Overview

- **Client**: Python CLI (`server_py/client/`) — key generation, encryption, upload, decryption, and CRUD on encrypted HR employee data. Requires PySEAL (`seal` package).
- **Server**: Python FastAPI (`server_py/`) — file-based storage; runs HE in Python (PySEAL) only. No C++ build.

### Cryptography (MVP)

- **Scheme**: Microsoft SEAL **BFV** (integer arithmetic). Salary and hours are integers (e.g. salary in cents).
- **Secure computations (server-side on ciphertext)**:
  1. **Total payroll** — sum of salaries.
  2. **Average salary** — server returns encrypted sum + plaintext count; client decrypts and divides locally.
  3. **Total hours** — sum of hours.
  4. **Bonus pool** — server returns encrypted sum(salary); client computes `bonus_pool = sum * BONUS_RATE_BPS / 10000` after decryption.

### Threat model

- **Honest-but-curious server**: follows the protocol but must not learn individual salaries/hours.
- **Secret key (SK)** is only on the client. **SK must never be uploaded.**

---

## Run (Python only)

### Prerequisites

- Python 3.10+, pip
- **PySEAL** for HE (client encrypt/decrypt and server compute). Install separately, e.g. [Huelse/SEAL-Python](https://github.com/Huelse/SEAL-Python).

### 1. Server

```bash
cd server_py
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

If PySEAL is not installed, `/v1/compute/*` will return 503 (HE engine unavailable).

### 2. Client (from repo root)

Set `PYTHONPATH` so the client package is found:

```bash
export PYTHONPATH="$(pwd)/server_py:$PYTHONPATH"
python3 -m client.cli init-context --poly 8192
python3 -m client.cli keygen
python3 -m client.cli encrypt-hr
python3 -m client.cli upload-session --session-id my-session
python3 -m client.cli upload-data --session-id my-session
python3 -m client.cli compute --session-id my-session
# Then fetch-decrypt each job_id printed by compute
python3 -m client.cli fetch-decrypt --job-id <job_id>
```

CRUD employees:

```bash
python3 -m client.cli employee create --session-id my-session --employee-id 1001 --from-csv
python3 -m client.cli employee list --session-id my-session
python3 -m client.cli employee get --session-id my-session --employee-id 1001
python3 -m client.cli employee delete --session-id my-session --employee-id 1001
```

Default server URL: `http://127.0.0.1:8000` (override with `--server`).

### 3. Tests (optional)

```bash
cd server_py
pip install -r requirements.txt
pytest tests/ -v
```

### 4. End-to-end demo

From repo root:

```bash
chmod +x demo.sh
./demo.sh
```

Runs server and Python client (init-context → keygen → encrypt-hr → upload → compute → fetch-decrypt). Requires PySEAL for full flow.

---

## Client CLI

| Command | Description |
|--------|-------------|
| `init-context [--poly 4096\|8192]` | Create `out/params.seal` (default poly=8192). |
| `keygen` | Generate secret/public/relin keys under `out/`. **Never upload secret_key.seal.** |
| `encrypt-hr [--csv path]` | Read `data/employees.csv`; write `out/salary.ct`, `out/hours.ct`, `out/bonus_points.ct`, `out/meta.json`. |
| `upload-session [--server URL] [--session-id ID]` | POST keys to `/v1/session/keys`. |
| `upload-data --session-id ID [--server URL]` | POST ciphertexts to `/v1/session/data`. |
| `compute --session-id ID [--server URL] [--bonus-bps 1000]` | Trigger total_payroll, avg_salary, total_hours, bonus_pool; prints job_ids. |
| `fetch-decrypt --job-id ID [--server URL]` | GET result and decrypt; print value. |
| `employee create --session-id ID --employee-id ID [--from-csv]` | Create or replace one employee (optionally encrypt from CSV row). |
| `employee list --session-id ID` | List employee_ids. |
| `employee get --session-id ID --employee-id ID` | Get encrypted payload. |
| `employee delete --session-id ID --employee-id ID` | Remove employee. |

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

### CRUD: HR employees

- `POST /v1/session/{session_id}/employees` — body: `employee_id`, `salary_ct_b64`, `hours_ct_b64`, `bonus_points_ct_b64`
- `GET /v1/session/{session_id}/employees` — list `employee_ids` and `count`
- `GET /v1/session/{session_id}/employees/{employee_id}` — get encrypted payload
- `PUT /v1/session/{session_id}/employees/{employee_id}` — update (path and body `employee_id` must match)
- `DELETE /v1/session/{session_id}/employees/{employee_id}` — remove employee data

---

## File-based storage

- **Config**: Set `HOMOLOCK_DATA_DIR` to the base directory (default: `./data` relative to the server cwd).
- **Layout**:
  - `data/db/sessions.json` — session metadata (paths, count, `employees`, timestamps).
  - `data/db/jobs.json` — job metadata.
  - `data/blobs/sessions/<session_id>/` — params.seal, keys, salary.ct/hours.ct/bonus_points.ct and/or `employees/<employee_id>/*.ct`.
  - `data/blobs/jobs/<job_id>/` — HE inputs and `result.ct`.
- File locking (portalocker) and atomic JSON writes for concurrency.

---

## Deploy on EC2

### 1. Launch instance

- **AMI**: Ubuntu 22.04 LTS.
- **Instance type**: e.g. `t3.small` (PySEAL can use some CPU/memory).
- **Security group**: allow **SSH (22)** and **TCP 8000** (or your chosen port) from your IP or `0.0.0.0/0` if you need public access.

### 2. Connect and install system deps

```bash
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>
sudo apt update
sudo apt install -y python3.10 python3.10-venv python3-pip git build-essential cmake
```

`build-essential` and `cmake` are needed only if you install PySEAL from source on the server.

### 3. Clone and set up the app

```bash
cd ~
git clone <YOUR_REPO_URL> Homolock
cd Homolock
```

### 4. Python venv and dependencies

```bash
cd server_py
python3.10 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**PySEAL on the server (for HE compute):**  
If you have a prebuilt `seal` wheel for your platform, install it with `pip install seal`. Otherwise build from source, e.g. [Huelse/SEAL-Python](https://github.com/Huelse/SEAL-Python) (requires CMake and a C++ toolchain on the instance). Without `seal`, the server runs but `/v1/compute/*` will return 503.

### 5. Data directory and env

```bash
sudo mkdir -p /var/lib/homolock
sudo chown ubuntu:ubuntu /var/lib/homolock
export HOMOLOCK_DATA_DIR=/var/lib/homolock
```

### 6. Run the server

**One-off (foreground):**

```bash
cd ~/Homolock/server_py
source .venv/bin/activate
export HOMOLOCK_DATA_DIR=/var/lib/homolock
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**With systemd (recommended):** create `/etc/systemd/system/homolock.service`:

```ini
[Unit]
Description=HomoLock-HR FastAPI server
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/Homolock/server_py
Environment="PATH=/home/ubuntu/Homolock/server_py/.venv/bin"
Environment="HOMOLOCK_DATA_DIR=/var/lib/homolock"
ExecStart=/home/ubuntu/Homolock/server_py/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable homolock
sudo systemctl start homolock
sudo systemctl status homolock
```

### 7. Use the client from your machine

From your laptop (with the repo and Python client):

```bash
export PYTHONPATH="$(pwd)/server_py:$PYTHONPATH"
python3 -m client.cli upload-session --server http://<EC2_PUBLIC_IP>:8000 --session-id my-session
python3 -m client.cli compute --session-id my-session --server http://<EC2_PUBLIC_IP>:8000
# etc.
```

Replace `<EC2_PUBLIC_IP>` with your instance’s public IPv4. For HTTPS and a domain, put a reverse proxy (e.g. Nginx or Caddy) in front of the app and use TLS.

---

## Limitations

- **BFV**: Integer-only; no real-number division on ciphertext.
- **PySEAL required**: Server and client need the `seal` package for HE; no C++ worker fallback.
- Storage is file-based; no auth.

Never upload `secret_key.seal` to the server or any untrusted host.
