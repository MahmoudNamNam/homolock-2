# HomoLock-HR

Privacy-preserving HR/Payroll computations using **Homomorphic Encryption (HE)**. Employees’ sensitive values (salary, hours, bonus inputs) are encrypted on the **client**; the **cloud server** computes on ciphertext **without ever decrypting** and never receives the secret key.

## Overview

- **Client**: Python CLI (`server_py/client/`) — key generation, encryption, upload, decryption, and CRUD on encrypted HR employee data. Requires PySEAL (`seal` package).
- **Server**: Python FastAPI (`server_py/`) — file-based storage; runs HE in Python (PySEAL) only.

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

## Quick start

**1. Install dependencies.** From repo root:

```bash
cd server_py
pip install -r requirements.txt
```

**PySEAL** (required for encrypt/decrypt and server compute): try `pip install seal` first. If no wheel is available, build from source, e.g. [Huelse/SEAL-Python](https://github.com/Huelse/SEAL-Python), or run `server_py/install_seal_python.sh` (see script comment: use only if you need to build from source).

**2. Start the server** (one terminal):

```bash
cd server_py
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**3. Run the full flow** (another terminal, from repo root):

```bash
export PYTHONPATH="$(pwd)/server_py:$PYTHONPATH"
python3 -m client.cli run
```

This runs: init-context → keygen → encrypt-hr (from `data/employees.csv`) → upload → compute → fetch-decrypt, and prints the four results (total payroll, avg salary, total hours, bonus pool). Use `--server http://HOST:8000` if the server is not on localhost.

**Or run the demo** (starts server in background + runs the client):

```bash
./demo.sh
```

---

## Step-by-step (optional)

If you prefer to run each step yourself:

**1. Start the server** (one terminal): `cd server_py && uvicorn app.main:app --host 0.0.0.0 --port 8000`

**2. Client** (from repo root):

```bash
export PYTHONPATH="$(pwd)/server_py:$PYTHONPATH"
python3 -m client.cli init-context              # creates out/params.seal
python3 -m client.cli keygen                    # creates keys in out/
python3 -m client.cli encrypt-hr                # reads data/employees.csv or --json data/employees.json → out/*.ct
python3 -m client.cli upload-session --session-id my-session
python3 -m client.cli upload-data --session-id my-session
python3 -m client.cli compute --session-id my-session   # prints 4 job_ids
python3 -m client.cli fetch-decrypt --job-id <job_id>   # repeat for each job_id
```

---

## CRUD employees (optional)

Add, list, get, or delete one employee at a time:

```bash
python3 -m client.cli employee create --session-id my-session --employee-id 1001 --from-csv
python3 -m client.cli employee list --session-id my-session
python3 -m client.cli employee get --session-id my-session --employee-id 1001
python3 -m client.cli employee delete --session-id my-session --employee-id 1001
```

---

## Run (Python only)

### Prerequisites

- Python 3.10+, pip
- **PySEAL** for HE: try `pip install seal` first; otherwise build from source (e.g. [Huelse/SEAL-Python](https://github.com/Huelse/SEAL-Python)) or use `server_py/install_seal_python.sh`.

### 1. Server

```bash
cd server_py
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

If PySEAL is not installed, `/v1/compute/*` will return 503 (HE engine unavailable).

### 2. Client (from repo root)

Set `PYTHONPATH` and run the full flow in one command:

```bash
export PYTHONPATH="$(pwd)/server_py:$PYTHONPATH"
python3 -m client.cli run
```

Or run step-by-step: `init-context --poly 8192`, `keygen`, `encrypt-hr`, `upload-session --session-id my-session`, `upload-data --session-id my-session`, `compute --session-id my-session`, then `fetch-decrypt --job-id <job_id>` for each result.

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

From repo root: `chmod +x demo.sh && ./demo.sh`. Starts the server and runs `client.cli run`. Requires PySEAL for full flow.

---

## Client CLI

| Command | Description |
|--------|-------------|
| `run [--server URL] [--session-id ID] [--csv path] [--poly 4096\|8192] [--bonus-bps N] [--no-decrypt]` | Full flow: init → keygen → encrypt → upload → compute → fetch-decrypt (prints four results). Use `--no-decrypt` to stop after compute and print job_ids only. |
| `init-context [--poly 4096\|8192]` | Create `out/params.seal` (default poly=8192). |
| `keygen` | Generate secret/public/relin keys under `out/`. **Never upload secret_key.seal.** |
| `encrypt-hr [--csv path \| --json path]` | Read employees from CSV or JSON (array of `{employee_id, salary_cents, hours, bonus_points}`); write `out/salary.ct`, `out/hours.ct`, `out/bonus_points.ct`, `out/meta.json`. |
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

All endpoints are relative to the server base URL (e.g. `http://localhost:8000`). Paths and storage are relative to `HOMOLOCK_DATA_DIR` (default `data/`).

- **Swagger UI:** `http://localhost:8000/docs` when the server is running.
- **Postman:** Import `server_py/postman/HomoLock-HR.postman_collection.json` and see `server_py/postman/POSTMAN.md` for how to run all endpoints.

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness. Response: `{"status":"ok"}`. |

### One-shot run (zero config)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/run` | Upload keys + data and run all four computations. **Body optional:** omit or send `{}` to use static data from `server_py/static/` (run `python -m scripts.generate_static_data` once). With body: all fields optional; omit `params_b64` to use static. Response: `{"session_id": "...", "job_ids": {"total_payroll": "...", "avg_salary": "...", "total_hours": "...", "bonus_pool": "..."}}`. |

### Session (keys and batch data)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/session/keys` | Create session with HE params and public keys. Body: `session_id`, `params_b64`, `public_key_b64`, `relin_keys_b64`, optional `galois_keys_b64`. |
| `POST` | `/v1/session/data` | Upload batch ciphertexts for a session. Body: `session_id`, `salary_ct_b64`, `hours_ct_b64`, `bonus_points_ct_b64`, `count`. |

### Compute

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/compute/total_payroll` | Body: `session_id`. Response: `{"job_id": "..."}`. |
| `POST` | `/v1/compute/avg_salary` | Body: `session_id`. Response: `{"job_id": "...", "count": N}`. |
| `POST` | `/v1/compute/total_hours` | Body: `session_id`. Response: `{"job_id": "..."}`. |
| `POST` | `/v1/compute/bonus_pool` | Body: `session_id`, optional `bonus_rate_bps` (default 1000). Response: `{"job_id": "...", "bonus_rate_bps": N}`. |

### Results

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/result/{job_id}` | Get job result. Response: `status`, `result_ciphertext_b64`, `result_type`, optional `count`, `bonus_rate_bps`. Decrypt `result_ciphertext_b64` locally with the secret key. |

### CRUD: employees (per-employee encrypted data)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/session/{session_id}/employees` | Create or replace one employee. Body: `employee_id`, `salary_ct_b64`, `hours_ct_b64`, `bonus_points_ct_b64`. |
| `GET` | `/v1/session/{session_id}/employees` | List employee IDs. Response: `employee_ids`, `count`. |
| `GET` | `/v1/session/{session_id}/employees/{employee_id}` | Get one employee’s encrypted payload. |
| `PUT` | `/v1/session/{session_id}/employees/{employee_id}` | Update employee (body `employee_id` must match path). |
| `DELETE` | `/v1/session/{session_id}/employees/{employee_id}` | Remove employee data. |

### Using only the API (everything from endpoints)

Keys and encryption stay on the client (never send the secret key). Two options:

- **Zero config:** Run `python -m scripts.generate_static_data` once, then `POST /v1/run` with body `{}`. Use `scripts.fetch_and_decrypt_results` to see decrypted results.
- **Custom data:** Generate keys and encrypt with the CLI (`init-context`, `keygen`, `encrypt-hr`), then `POST /v1/run` with full body (or `POST /v1/session/keys` + `POST /v1/session/data` + the four `POST /v1/compute/*`), then `GET /v1/result/{job_id}` for each and decrypt locally.

### Static keys and ciphertexts

To get fixed keys and ciphertexts for testing or for calling `POST /v1/run` without running the full CLI each time:

```bash
cd server_py
python -m scripts.generate_static_data
```

This writes to `server_py/static/`: `params.seal`, `public_key.seal`, `relin_keys.seal`, optional `galois_keys.seal`, `secret_key.seal`, `salary.ct`, `hours.ct`, `bonus_points.ct`, `meta.json` (5 fixed demo rows). Base64-encode these files (except `secret_key.seal`) for the request body; use `secret_key.seal` locally to decrypt results. Do not upload the secret key.

**See real (decrypted) results after `POST /v1/run`:** pipe the run response into the decrypt script (from `server_py`):
```bash
curl -s -X POST http://localhost:8000/v1/run -H "Content-Type: application/json" -d '{}' | python -m scripts.fetch_and_decrypt_results --server http://localhost:8000
```
This fetches each job result and decrypts with `static/secret_key.seal`, then prints total payroll, avg salary, total hours, and bonus pool.

### CRUD: HR employees

- `POST /v1/session/{session_id}/employees` — body: `employee_id`, `salary_ct_b64`, `hours_ct_b64`, `bonus_points_ct_b64`
- `GET /v1/session/{session_id}/employees` — list `employee_ids` and `count`
- `GET /v1/session/{session_id}/employees/{employee_id}` — get encrypted payload
- `PUT /v1/session/{session_id}/employees/{employee_id}` — update (path and body `employee_id` must match)
- `DELETE /v1/session/{session_id}/employees/{employee_id}` — remove employee data

---

## File-based storage

- **Config**: Set `HOMOLOCK_DATA_DIR` to the base directory (default: `./data` relative to the server cwd).
- **Layout** (single unified dir under `HOMOLOCK_DATA_DIR`):
  - `data/sessions.json` — session metadata (paths, count, `employees`, timestamps).
  - `data/jobs.json` — job metadata.
  - `data/sessions/<session_id>/` — params.seal, keys, salary.ct/hours.ct/bonus_points.ct and/or `employees/<employee_id>/*.ct`.
  - `data/jobs/<job_id>/` — HE inputs and `result.ct`.
- File locking (portalocker) and atomic JSON writes for concurrency.

---

## Deploy on EC2

### Quick setup & run (copy-paste on the instance)

After launching Ubuntu 22.04 and opening **port 8000** in the security group:

```bash
# 1. SSH in
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>

# 2. One-time setup (run once)
sudo apt update && sudo apt install -y python3.10 python3.10-venv python3-pip git
cd ~
git clone <YOUR_REPO_URL> Homolock
cd Homolock/server_py
python3.10 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo mkdir -p /var/lib/homolock && sudo chown ubuntu:ubuntu /var/lib/homolock

# 3. Run the server (foreground)
export HOMOLOCK_DATA_DIR=/var/lib/homolock
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Then from your laptop: use the client with `--server http://<EC2_PUBLIC_IP>:8000`.  
For a persistent server (survives logout), use the systemd steps below.

---

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
If you have a prebuilt `seal` wheel for your platform, install it with `pip install seal`. Otherwise build from source, e.g. [Huelse/SEAL-Python](https://github.com/Huelse/SEAL-Python). Without `seal`, the server runs but `/v1/compute/*` will return 503.

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

**Run the app in the cloud (any provider):** See **`server_py/docs/RUN-IN-CLOUD.md`** for VM or container steps (AWS, GCP, Azure, DigitalOcean, etc.). **Using the API when deployed:** See **`server_py/docs/DEPLOY-AWS.md`** for how to call the API from Postman, CLI, or cURL once the server is running (base URL, one-shot run, static data).

---

**Seeing actual data and which operations are allowed:** See **`server_py/docs/DATA_AND_OPS.md`** (aggregate vs per-employee decryption, server ops = sum/count only, client ops = anything on plaintext).

## Limitations

- **BFV**: Integer-only; no real-number division on ciphertext.
- **Decoded results**: Large sums can wrap in the plaintext space; the client and decrypt scripts normalize negative decoded values using the plain modulus (Batching bit size 20) so aggregates display as intended.
- **PySEAL required**: Server and client need the `seal` package for HE.
- Storage is file-based; no auth.

Never upload `secret_key.seal` to the server or any untrusted host.
